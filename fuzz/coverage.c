// 基于 QEMU 主循环的覆盖率采集模块
//
// 覆盖率记录逻辑从 TCG 插件移入主循环后，本模块负责：
//   - 解析 -fuzz 参数指定的 JSON 配置文件与目标 ELF
//   - 在 TB 执行出口记录覆盖率（由 accel/tcg/cpu-exec.c 调用）
//   - 内部使用 GHashTable 存储 TB 映射、链表存储执行 trace，
//     不再依赖固定大小的共享内存数组
//   - 维护 AFL 兼容的边覆盖 bitmap，测试结束后由 forkserver 拷贝到共享内存
//
// 五种识别模式（FuzzConfig.mode）：
//   - mode 0 已知入口+ELF 指纹：解析 ELF 获得入口地址、.text 范围与入口指令，
//     仅在 entry_addr 匹配的 TB 上指纹比对识别目标，按 ASID 与虚拟 .text 范围过滤
//   - mode 1 ASLR+ELF 自动定位：解析 ELF 获得入口指令，在每个新 TB 上指纹比对，
//     识别后计算 ASLR 偏移并同步调整 .text 范围，按 ASID 与调整后范围过滤
//   - mode 2 ASLR 全范围扫描：不解析 ELF，不限制 .text 范围，覆盖全部地址空间
//   - mode 3 手动输入指纹字段：手动填入 entry_addr 与完整 entry_code，
//     过滤方式同 mode 0
//   - mode 4 子进程模式：手动填入指纹字段，不依赖 ASID 与 elf_path，
//     识别后记录入口物理地址，按连续性推导出 .text 物理范围（供 exec 出的子进程使用）
#include "qemu/osdep.h"
#include "exec/cpu-common.h"
#include "fuzz/coverage.h"

#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>

#include "elf.h"

// 日志
static FILE *log_fp;
static const char *log_path = "Logs/coverage.log";

// 覆盖率内部数据
static GMutex lock;
static FuzzConfig config;
// key: virt_addr，value: CoverageEntry
static GHashTable *tb_map;
// 执行 trace 链表头
static FuzzTraceEntry *trace_head;
// 执行 trace 链表尾
static FuzzTraceEntry *trace_tail;
static uint32_t trace_count;
static uint8_t edge_bitmap[EDGE_MAP_SIZE];
static uint32_t prev_loc_exec;

// 快照时的覆盖率备份（每轮测试前恢复到该状态）
static GHashTable *backup_tb_map;
static FuzzTraceEntry *backup_trace_head;
static FuzzTraceEntry *backup_trace_tail;
static uint32_t backup_trace_count;
static uint8_t backup_edge_bitmap[EDGE_MAP_SIZE];
static uint32_t backup_prev_loc_exec;
static bool has_backup;

// 自动保存快照通知管道写端（auto_snapshot 时打开）
static int auto_snap_fd = -1;

// 目标识别状态
static bool target_found;
static uint64_t target_asid;
// mode 4 子进程模式：由入口物理地址推导的 .text 物理范围起始
static uint64_t text_phys_start;
// 运行时 .text 范围（ASLR 调整后）
static uint64_t text_start;
static uint64_t text_size;
// 入口指纹字节
static uint8_t expected_bytes[ENTRY_INSTR_COUNT * 4];

// 日志处理函数
static void log_handler(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer fp) {
	g_autoptr(GDateTime) now = g_date_time_new_now_local();
	g_autofree gchar *ts = g_date_time_format(now, "%Y-%m-%d %H:%M:%S");
	const char *tag;

	if (level & G_LOG_LEVEL_ERROR) {
		tag = "ERROR";
	} else if (level & G_LOG_LEVEL_CRITICAL) {
		tag = "CRITICAL";
	} else if (level & G_LOG_LEVEL_WARNING) {
		tag = "WARNING";
	} else if (level & G_LOG_LEVEL_MESSAGE) {
		tag = "MESSAGE";
	} else if (level & G_LOG_LEVEL_INFO) {
		tag = "INFO";
	} else if (level & G_LOG_LEVEL_DEBUG) {
		tag = "DEBUG";
	} else {
		tag = "LOG";
	}
	fprintf((FILE *)fp, "[%s] [%s] %s\n", ts, tag, message);
	fflush((FILE *)fp);
}

static inline uint16_t be16(uint16_t x) { return __builtin_bswap16(x); }
static inline uint32_t be32(uint32_t x) { return __builtin_bswap32(x); }
static inline uint64_t be64(uint64_t x) { return __builtin_bswap64(x); }

// 将入口指令转为大端字节序列（指纹比对用）
static void instrs_to_bytes(const FuzzConfig *cfg, uint8_t buf[ENTRY_INSTR_COUNT * 4]) {
	for (size_t i = 0; i < ENTRY_INSTR_COUNT; i++) {
		uint32_t v = cfg->instrs[i];
		buf[i * 4] = (v >> 24) & 0xff;
		buf[i * 4 + 1] = (v >> 16) & 0xff;
		buf[i * 4 + 2] = (v >> 8) & 0xff;
		buf[i * 4 + 3] = v & 0xff;
	}
}

// 从字节缓冲区解析入口指令（大端 uint32_t）
static void bytes_to_instrs(uint8_t *buf, size_t len, FuzzConfig *cfg) {
	size_t n = len > ENTRY_INSTR_COUNT * 4 ? ENTRY_INSTR_COUNT * 4 : len;
	cfg->instr_count = n / 4;
	for (size_t i = 0; i < n; i += 4) {
		cfg->instrs[i / 4] =
			((uint32_t)buf[i] << 24) |
			((uint32_t)buf[i + 1] << 16) |
			((uint32_t)buf[i + 2] << 8) |
			(uint32_t)buf[i + 3];
	}
}

// 解析 JSON 配置文件（逐行手写解析，兼容现有配置格式）
static bool parse_config(const char *path, FuzzConfig *cfg) {
	g_autofree char *content = NULL;
	gsize len;
	if (!g_file_get_contents(path, &content, &len, NULL)) {
		return false;
	}

	memset(cfg, 0, sizeof(*cfg));

	g_auto(GStrv) lines = g_strsplit(content, "\n", 0);
	int list_count = 0;
	gboolean in_list = FALSE;
	gboolean in_types = FALSE;
	gboolean seen_types = FALSE;

	for (int i = 0; lines[i]; i++) {
		g_autofree char *raw_line = g_strdup(lines[i]);
		char *line = g_strstrip(raw_line);

		if (line[0] == '\0' || line[0] == '/' || line[0] == '#' || line[0] == '{' || line[0] == '}') {
			continue;
		}

		if (in_types) {
			// coverage_types 数组：字符串元素，指定收集哪些类型的覆盖率
			if (line[0] == '"') {
				const char *val = line + 1;
				const char *end = strchr(val, '"');
				if (end) {
					g_autofree char *v = g_strndup(val, end - val);
					if (g_strcmp0(v, "block") == 0) {
						cfg->cov_block = TRUE;
					} else if (g_strcmp0(v, "edge") == 0) {
						cfg->cov_edge = TRUE;
					} else if (g_strcmp0(v, "trace") == 0) {
						cfg->cov_trace = TRUE;
					}
				}
				continue;
			}
			in_types = FALSE;
			continue;
		}

		if (in_list) {
			if (line[0] == '"') {
				const char *val = line + 1;
				const char *end = strchr(val, '"');
				if (end) {
					g_autofree char *v = g_strndup(val, end - val);
					if (list_count < ENTRY_INSTR_COUNT) {
						cfg->instrs[list_count] = (uint32_t)g_ascii_strtoull(v, NULL, 16);
						cfg->instr_count = list_count + 1;
					}
					list_count++;
				}
				continue;
			}
			in_list = FALSE;
		}

		g_auto(GStrv) kv = g_strsplit(line, ":", 2);
		if (!kv[0] || !kv[1]) {
			continue;
		}
		g_autofree char *key_raw = g_strdup(kv[0]);
		g_autofree char *val_raw = g_strdup(kv[1]);
		char *key = g_strstrip(key_raw);
		char *val = g_strstrip(val_raw);

		if (key[0] == '"') {
			key++;
		}
		size_t klen = strlen(key);
		if (klen > 1 && key[klen - 1] == '"') {
			key[klen - 1] = '\0';
		}

		size_t vlen = strlen(val);
		if (vlen > 0 && val[vlen - 1] == ',') {
			val[--vlen] = '\0';
		}
		if (vlen > 0 && val[vlen - 1] == '"') {
			val[--vlen] = '\0';
		}
		if (val[0] == '"') {
			val++;
		}

		if (g_strcmp0(key, "mode") == 0) {
			cfg->mode = (int)g_ascii_strtoull(val, NULL, 10);
		} else if (g_strcmp0(key, "elf_path") == 0) {
			if (val[0] != '\0') {
				cfg->elf_path = g_strdup(val);
			}
		} else if (g_strcmp0(key, "entry_addr") == 0) {
			if (val[0] != '\0') {
				cfg->entry_addr = g_ascii_strtoull(val, NULL, 16);
			}
		} else if (g_strcmp0(key, "text_start") == 0) {
			if (val[0] != '\0') {
				cfg->text_start = g_ascii_strtoull(val, NULL, 16);
			}
		} else if (g_strcmp0(key, "text_size") == 0) {
			if (val[0] != '\0') {
				cfg->text_size = g_ascii_strtoull(val, NULL, 16);
			}
		} else if (g_strcmp0(key, "inst_ratio") == 0) {
			cfg->inst_ratio = (uint32_t)g_ascii_strtoull(val, NULL, 10);
		} else if (g_strcmp0(key, "wait_snapshot_restore") == 0) {
			cfg->wait_snapshot_restore_ms = g_ascii_strtoll(val, NULL, 10);
		} else if (g_strcmp0(key, "wait_program_done") == 0) {
			cfg->wait_program_done_ms = g_ascii_strtoll(val, NULL, 10);
		} else if (g_strcmp0(key, "debug") == 0) {
			cfg->debug = (g_strcmp0(val, "true") == 0 || g_strcmp0(val, "1") == 0);
		} else if (g_strcmp0(key, "auto_snapshot") == 0) {
			cfg->auto_snapshot = (g_strcmp0(val, "true") == 0 || g_strcmp0(val, "1") == 0);
		} else if (g_strcmp0(key, "entry_code") == 0) {
			in_list = TRUE;
			list_count = 0;
		} else if (g_strcmp0(key, "coverage_types") == 0) {
			seen_types = TRUE;
			in_types = TRUE;
		}
	}

	// 未配置 coverage_types 时默认全开（保持旧行为）
	if (!seen_types) {
		cfg->cov_block = TRUE;
		cfg->cov_edge = TRUE;
		cfg->cov_trace = TRUE;
	}

	return true;
}

// 解析目标 ELF，提取入口地址、.text 范围与入口指令
static bool parse_elf(const char *path, FuzzConfig *cfg) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return false;
	}

	uint8_t e_ident[EI_NIDENT];
	if (read(fd, e_ident, EI_NIDENT) != EI_NIDENT) {
		close(fd);
		return false;
	}

	if (e_ident[EI_CLASS] != ELFCLASS32 && e_ident[EI_CLASS] != ELFCLASS64) {
		close(fd);
		return false;
	}

	gboolean is_64 = (e_ident[EI_CLASS] == ELFCLASS64);

	uint64_t ehdr_entry;
	uint64_t ehdr_phoff;
	uint32_t ehdr_phnum;
	uint64_t ehdr_shoff;
	uint32_t ehdr_shnum;
	uint16_t ehdr_shstrndx;

	if (is_64) {
		Elf64_Ehdr ehdr;
		lseek(fd, 0, SEEK_SET);
		read(fd, &ehdr, sizeof(ehdr));
		ehdr_entry = be64(ehdr.e_entry);
		ehdr_phoff = be64(ehdr.e_phoff);
		ehdr_phnum = be16(ehdr.e_phnum);
		ehdr_shoff = be64(ehdr.e_shoff);
		ehdr_shnum = be16(ehdr.e_shnum);
		ehdr_shstrndx = be16(ehdr.e_shstrndx);
	} else {
		Elf32_Ehdr ehdr;
		lseek(fd, 0, SEEK_SET);
		read(fd, &ehdr, sizeof(ehdr));
		ehdr_entry = be32(ehdr.e_entry);
		ehdr_phoff = be32(ehdr.e_phoff);
		ehdr_phnum = be16(ehdr.e_phnum);
		ehdr_shoff = be32(ehdr.e_shoff);
		ehdr_shnum = be16(ehdr.e_shnum);
		ehdr_shstrndx = be16(ehdr.e_shstrndx);
	}

	uint64_t start_addr = ehdr_entry;

	// 在符号表中查找 _start
	for (uint32_t i = 0; i < ehdr_shnum; i++) {
		uint32_t sh_type;
		uint64_t sh_offset, sh_size, sh_link;

		if (is_64) {
			Elf64_Shdr shdr;
			lseek(fd, ehdr_shoff + i * sizeof(shdr), SEEK_SET);
			read(fd, &shdr, sizeof(shdr));
			sh_type = be32(shdr.sh_type);
			sh_offset = be64(shdr.sh_offset);
			sh_size = be64(shdr.sh_size);
			sh_link = be32(shdr.sh_link);
		} else {
			Elf32_Shdr shdr;
			lseek(fd, ehdr_shoff + i * sizeof(shdr), SEEK_SET);
			read(fd, &shdr, sizeof(shdr));
			sh_type = be32(shdr.sh_type);
			sh_offset = be32(shdr.sh_offset);
			sh_size = be32(shdr.sh_size);
			sh_link = be32(shdr.sh_link);
		}

		if (sh_type != SHT_SYMTAB) {
			continue;
		}

		uint64_t str_off;
		if (is_64) {
			Elf64_Shdr str_shdr;
			lseek(fd, ehdr_shoff + sh_link * sizeof(str_shdr), SEEK_SET);
			read(fd, &str_shdr, sizeof(str_shdr));
			str_off = be64(str_shdr.sh_offset);
		} else {
			Elf32_Shdr str_shdr;
			lseek(fd, ehdr_shoff + sh_link * sizeof(str_shdr), SEEK_SET);
			read(fd, &str_shdr, sizeof(str_shdr));
			str_off = be32(str_shdr.sh_offset);
		}

		uint64_t num = sh_size / (is_64 ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym));
		for (uint64_t j = 0; j < num; j++) {
			uint64_t sym_value;
			uint8_t sym_info;
			uint32_t sym_name;

			if (is_64) {
				Elf64_Sym sym;
				lseek(fd, sh_offset + j * sizeof(sym), SEEK_SET);
				read(fd, &sym, sizeof(sym));
				sym_name = be32(sym.st_name);
				sym_info = sym.st_info;
				sym_value = be64(sym.st_value);
			} else {
				Elf32_Sym sym;
				lseek(fd, sh_offset + j * sizeof(sym), SEEK_SET);
				read(fd, &sym, sizeof(sym));
				sym_name = be32(sym.st_name);
				sym_info = sym.st_info;
				sym_value = be32(sym.st_value);
			}

			if (ELF32_ST_TYPE(sym_info) != STT_FUNC) {
				continue;
			}

			char name[16];
			lseek(fd, str_off + sym_name, SEEK_SET);
			read(fd, name, sizeof(name));
			if (strcmp(name, "_start") == 0) {
				start_addr = sym_value;
				break;
			}
		}
		break;
	}

	cfg->entry_addr = start_addr;

	// 查找 .text 段范围
	uint64_t shstr_off = 0;
	if (is_64) {
		Elf64_Shdr shdr;
		lseek(fd, ehdr_shoff + ehdr_shstrndx * sizeof(shdr), SEEK_SET);
		read(fd, &shdr, sizeof(shdr));
		shstr_off = be64(shdr.sh_offset);
	} else {
		Elf32_Shdr shdr;
		lseek(fd, ehdr_shoff + ehdr_shstrndx * sizeof(shdr), SEEK_SET);
		read(fd, &shdr, sizeof(shdr));
		shstr_off = be32(shdr.sh_offset);
	}

	for (uint32_t i = 0; i < ehdr_shnum; i++) {
		uint32_t sh_name;
		uint64_t sh_addr, sh_size;

		if (is_64) {
			Elf64_Shdr shdr;
			lseek(fd, ehdr_shoff + i * sizeof(shdr), SEEK_SET);
			read(fd, &shdr, sizeof(shdr));
			sh_name = be32(shdr.sh_name);
			sh_addr = be64(shdr.sh_addr);
			sh_size = be64(shdr.sh_size);
		} else {
			Elf32_Shdr shdr;
			lseek(fd, ehdr_shoff + i * sizeof(shdr), SEEK_SET);
			read(fd, &shdr, sizeof(shdr));
			sh_name = be32(shdr.sh_name);
			sh_addr = be32(shdr.sh_addr);
			sh_size = be32(shdr.sh_size);
		}

		char name[16];
		lseek(fd, shstr_off + sh_name, SEEK_SET);
		read(fd, name, sizeof(name));
		if (strcmp(name, ".text") == 0) {
			cfg->text_start = sh_addr;
			cfg->text_size = sh_size;
			break;
		}
	}

	// 读取入口处指令作为指纹
	for (uint32_t i = 0; i < ehdr_phnum; i++) {
		uint32_t p_type;
		uint64_t p_offset, p_vaddr, p_filesz;

		if (is_64) {
			Elf64_Phdr phdr;
			lseek(fd, ehdr_phoff + i * sizeof(phdr), SEEK_SET);
			read(fd, &phdr, sizeof(phdr));
			p_type = be32(phdr.p_type);
			p_offset = be64(phdr.p_offset);
			p_vaddr = be64(phdr.p_vaddr);
			p_filesz = be64(phdr.p_filesz);
		} else {
			Elf32_Phdr phdr;
			lseek(fd, ehdr_phoff + i * sizeof(phdr), SEEK_SET);
			read(fd, &phdr, sizeof(phdr));
			p_type = be32(phdr.p_type);
			p_offset = be32(phdr.p_offset);
			p_vaddr = be32(phdr.p_vaddr);
			p_filesz = be32(phdr.p_filesz);
		}

		if (p_type == PT_LOAD && start_addr >= p_vaddr && start_addr < p_vaddr + p_filesz) {
			lseek(fd, p_offset + (start_addr - p_vaddr), SEEK_SET);
			uint8_t code_buf[ENTRY_INSTR_COUNT * 4];
			ssize_t n = read(fd, code_buf, sizeof(code_buf));
			bytes_to_instrs(code_buf, n > 0 ? (size_t)n : 0, cfg);
			break;
		}
	}

	close(fd);
	return true;
}

// 指纹比对：读取 guest 物理内存与入口指令字节比较，识别目标进程
static void fuzz_identify(uint64_t virt_addr, uint64_t phys_addr, uint64_t asid) {
	if (config.instr_count != ENTRY_INSTR_COUNT) {
		return;
	}

	uint8_t buf[ENTRY_INSTR_COUNT * 4];
	cpu_physical_memory_read(phys_addr, buf, sizeof(buf));
	if (memcmp(buf, expected_bytes, sizeof(buf)) != 0) {
		return;
	}

	target_found = true;
	target_asid = asid;
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "target process identified: ASID=0x%02" PRIx64, target_asid);

	// ASLR 模式：入口地址偏移量同步到 .text 范围
	if (config.mode == 1) {
		uint64_t offset = virt_addr - config.entry_addr;
		text_start += offset;
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "ASLR offset 0x%016" PRIx64 ", text_start adjusted to 0x%016" PRIx64, offset, text_start);
	}

	// 子进程模式：入口物理地址偏移量同步到 .text 物理范围
	if (config.mode == 4) {
		text_phys_start = phys_addr - virt_addr + text_start;
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "entry phys 0x%016" PRIx64 ", text_phys range: 0x%016" PRIx64 "-0x%016" PRIx64, phys_addr, text_phys_start, text_phys_start + text_size);
	}

	// 自动保存快照模式：通知 forkserver 在目标入口识别后保存快照
	if (auto_snap_fd >= 0) {
		unsigned char notify = 0x01;
		if (write(auto_snap_fd, &notify, 1) != 1) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "notify forkserver auto save failed");
		}
	}
}

// 记录一个已执行 TB 的覆盖率（主循环 TB 执行出口调用）
void fuzz_coverage_record_tb(uint64_t virt_addr, uint64_t phys_addr, uint32_t insn_count, uint64_t asid) {
	g_mutex_lock(&lock);

	// 目标已识别：模式 4 按 .text 物理范围过滤，其余按 ASID 与虚拟 .text 范围过滤
	if (target_found) {
		if (config.mode == 4) {
			if (virt_addr < text_start || virt_addr > text_start + text_size) {
				g_mutex_unlock(&lock);
				return;
			}
			if (phys_addr < text_phys_start || phys_addr > text_phys_start + text_size) {
				g_mutex_unlock(&lock);
				return;
			}
		} else {
			if (asid != target_asid) {
				g_mutex_unlock(&lock);
				return;
			}
			if (virt_addr < text_start || virt_addr > text_start + text_size) {
				g_mutex_unlock(&lock);
				return;
			}
		}
	} else if (asid == 0) {
		// 系统模式下 ASID 0 为内核代码，不参与目标识别
		g_mutex_unlock(&lock);
		return;
	} else if (config.mode == 0 || config.mode == 3 || config.mode == 4) {
		// 已知入口模式：仅在入口 TB 上尝试识别目标
		if (virt_addr != config.entry_addr) {
			g_mutex_unlock(&lock);
			return;
		}
	} else if (config.mode == 1 || config.mode == 2) {
		// ASLR 扫描模式：在每个新 TB 上尝试识别目标
	} else {
		g_mutex_unlock(&lock);
		return;
	}

	// 目标未识别：先在新 TB 上尝试指纹比对，失败则不记录该 TB
	if (!target_found && phys_addr != (uint64_t)-1) {
		fuzz_identify(virt_addr, phys_addr, asid);
	}
	if (!target_found) {
		g_mutex_unlock(&lock);
		return;
	}

	// block 覆盖：记录 TB 映射与执行次数
	if (config.cov_block) {
		CoverageEntry *e = g_hash_table_lookup(tb_map, &virt_addr);
		if (!e) {
			e = g_malloc0(sizeof(CoverageEntry));
			e->virt_addr = virt_addr;
			e->phys_addr = phys_addr;
			e->asid = asid;
			e->insn_count = insn_count;
			g_hash_table_insert(tb_map, &e->virt_addr, e);
		}
		e->exec_count++;
	}

	// 边覆盖：cur_loc 混淆 + prev_loc 差分，与 AFL 语义一致
	uint64_t cur_loc = (virt_addr >> 4) ^ (virt_addr << 8);
	cur_loc &= EDGE_MAP_SIZE - 1;

	if (config.cov_edge && cur_loc < config.inst_ratio) {
		uint32_t edge_idx = cur_loc ^ prev_loc_exec;
		edge_bitmap[edge_idx]++;
		prev_loc_exec = cur_loc >> 1;
	}

	// 执行 trace：与上一条同 cur_loc 则计数累加，否则追加新节点
	if (config.cov_trace && cur_loc < config.inst_ratio) {
		if (trace_count > 0 && trace_tail->cur_loc == (uint32_t)cur_loc) {
			trace_tail->exec_count++;
		} else {
			FuzzTraceEntry *t = g_malloc0(sizeof(FuzzTraceEntry));
			t->virt_addr = virt_addr;
			t->cur_loc = (uint32_t)cur_loc;
			t->exec_count = 1;
			if (trace_tail) {
				trace_tail->next = t;
			} else {
				trace_head = t;
			}
			trace_tail = t;
			trace_count++;
		}
	}

	g_mutex_unlock(&lock);
}

// 深拷贝 TB 映射表（key 为条目内 virt_addr 的地址，需逐条重建）
static GHashTable *copy_tb_map(GHashTable *src) {
	GHashTable *dst = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, src);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		CoverageEntry *e = value;
		CoverageEntry *copy = g_malloc0(sizeof(CoverageEntry));
		*copy = *e;
		g_hash_table_insert(dst, &copy->virt_addr, copy);
	}
	return dst;
}

// 深拷贝执行 trace 链表
static FuzzTraceEntry *copy_trace(FuzzTraceEntry *head, FuzzTraceEntry **tail, uint32_t *count) {
	FuzzTraceEntry *new_head = NULL;
	FuzzTraceEntry *new_tail = NULL;
	uint32_t n = 0;
	for (FuzzTraceEntry *t = head; t; t = t->next) {
		FuzzTraceEntry *copy = g_malloc0(sizeof(FuzzTraceEntry));
		*copy = *t;
		copy->next = NULL;
		if (new_tail) {
			new_tail->next = copy;
		} else {
			new_head = copy;
		}
		new_tail = copy;
		n++;
	}
	*tail = new_tail;
	*count = n;
	return new_head;
}

// 释放执行 trace 链表
static void free_trace(FuzzTraceEntry *head) {
	while (head) {
		FuzzTraceEntry *next = head->next;
		g_free(head);
		head = next;
	}
}

// 将当前覆盖率状态深拷贝为备份（save_snapshot 成功后调用）
void fuzz_coverage_backup(void) {
	g_mutex_lock(&lock);

	if (backup_tb_map) {
		g_hash_table_destroy(backup_tb_map);
	}
	free_trace(backup_trace_head);

	backup_tb_map = copy_tb_map(tb_map);
	backup_trace_head = copy_trace(trace_head, &backup_trace_tail, &backup_trace_count);
	memcpy(backup_edge_bitmap, edge_bitmap, sizeof(backup_edge_bitmap));
	backup_prev_loc_exec = prev_loc_exec;
	has_backup = true;

	g_mutex_unlock(&lock);
}

// 是否开启自动保存快照（识别到目标入口后自动保存）
bool fuzz_coverage_auto_snapshot(void) {
	return config.auto_snapshot;
}

// 快照恢复后到发送 status 前的等待时间（毫秒）
int64_t fuzz_coverage_wait_snapshot_restore_ms(void) {
	return config.wait_snapshot_restore_ms;
}

// 结束本轮测试前等待程序处理的时间（毫秒）
int64_t fuzz_coverage_wait_program_done_ms(void) {
	return config.wait_program_done_ms;
}

// 重置本轮测试的覆盖率数据（恢复为保存快照时的状态，无备份时全清零）
void fuzz_coverage_reset(void) {
	g_mutex_lock(&lock);
	g_hash_table_destroy(tb_map);
	free_trace(trace_head);
	trace_head = NULL;
	trace_tail = NULL;
	trace_count = 0;

	if (has_backup) {
		tb_map = copy_tb_map(backup_tb_map);
		trace_head = copy_trace(backup_trace_head, &trace_tail, &trace_count);
		memcpy(edge_bitmap, backup_edge_bitmap, sizeof(edge_bitmap));
		prev_loc_exec = backup_prev_loc_exec;
	} else {
		tb_map = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
		memset(edge_bitmap, 0, sizeof(edge_bitmap));
		prev_loc_exec = 0;
	}
	g_mutex_unlock(&lock);
}

// 将内部 edge bitmap 拷贝到共享内存供 AFLNet 读取
void fuzz_coverage_copy_edge_map(uint8_t *dst) {
	g_mutex_lock(&lock);
	memcpy(dst, edge_bitmap, EDGE_MAP_SIZE);
	g_mutex_unlock(&lock);
}

// 输出覆盖率信息，fuzz_count 为第几次 fuzz 的覆盖率，快照刚保存未开始 fuzz 时传 0
void fuzz_coverage_dump(uint64_t fuzz_count) {
	g_mutex_lock(&lock);

	if (fuzz_count == 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "coverage captured at snapshot save, before any fuzz round");
	} else {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "coverage after fuzz round #%" PRIu64, fuzz_count);
	}

	if (config.cov_block) {
		uint32_t tb_count = g_hash_table_size(tb_map);
		if (config.debug) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s,%s,%s,%s,%s", "virt_addr", "phys_addr", "asid", "exec_count", "insn_count");
			GHashTableIter iter;
			gpointer key, value;
			g_hash_table_iter_init(&iter, tb_map);
			while (g_hash_table_iter_next(&iter, &key, &value)) {
				CoverageEntry *e = value;
				g_log(
					LOG_DOMAIN,
					G_LOG_LEVEL_DEBUG,
					"0x%016" PRIx64 ",0x%016" PRIx64 ",0x%02" PRIx64 ",%" PRIu64 ",%" PRIu64,
					e->virt_addr,
					e->phys_addr,
					e->asid,
					e->exec_count,
					e->insn_count
				);
			}
		}
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "%u TB entries collected", tb_count);
	}

	if (config.cov_edge) {
		uint32_t edge_count = 0;
		for (uint32_t i = 0; i < EDGE_MAP_SIZE; i++) {
			if (edge_bitmap[i] != 0) {
				edge_count++;
			}
		}
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "edge coverage: %" PRIu32 " edges hit", edge_count);
	}

	if (config.cov_trace) {
		if (config.debug) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s,%s,%s", "virt_addr", "cur_loc", "exec_count");
			for (FuzzTraceEntry *t = trace_head; t; t = t->next) {
				g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "0x%016" PRIx64 ",0x%08" PRIx32 ",%" PRIu32, t->virt_addr, t->cur_loc, t->exec_count);
			}
		}
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "execution trace: %" PRIu32 " entries", trace_count);
	}

	g_mutex_unlock(&lock);
}

// 初始化覆盖率模块
void fuzz_coverage_init(const char *config_path) {
	if (!config_path || config_path[0] == '\0') {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "config path required");
		return;
	}

	// 初始化日志
	g_mkdir_with_parents("Logs", 0755);
	log_fp = fopen(log_path, "w");
	if (log_fp) {
		g_log_set_handler(LOG_DOMAIN, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL, log_handler, log_fp);
	}

	// 解析配置文件
	if (!parse_config(config_path, &config)) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "failed to parse config: %s", config_path);
		return;
	}

	// 模式 0/1：需要 elf_path 解析入口与指纹
	if ((config.mode == 0 || config.mode == 1) && (!config.elf_path || config.elf_path[0] == '\0')) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mode %d requires elf_path in config", config.mode);
		return;
	}
	if (config.mode == 0 || config.mode == 1) {
		if (!parse_elf(config.elf_path, &config)) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "failed to parse ELF: %s", config.elf_path);
			return;
		}
	}

	// 全范围扫描模式：不过滤 .text 范围
	if (config.mode == 2) {
		config.text_start = 0;
		config.text_size = UINT64_MAX;
		config.entry_addr = 0;
	}

	// 手动指纹模式（3/4）：必须提供完整 entry_code
	if (config.mode == 3 || config.mode == 4) {
		if (config.instr_count != ENTRY_INSTR_COUNT) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mode %d requires entry_code with %d instructions", config.mode, ENTRY_INSTR_COUNT);
			return;
		}
	}

	// 子进程模式：必须提供 .text 范围用于推导物理过滤范围
	if (config.mode == 4 && (config.text_start == 0 || config.text_size == 0)) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mode 4 requires text_start and text_size in config");
		return;
	}

	if (config.mode < 0 || config.mode > 4) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "invalid mode %d, must be 0-4", config.mode);
		return;
	}

	if (config.inst_ratio > EDGE_MAP_SIZE) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "inst_ratio %" PRIu32 " exceeds EDGE_MAP_SIZE", config.inst_ratio);
		return;
	}

	// 初始化数据结构
	tb_map = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
	instrs_to_bytes(&config, expected_bytes);
	text_start = config.text_start;
	text_size = config.text_size;

	// 自动保存快照模式：打开通知管道写端（由 forkserver 创建）
	if (config.auto_snapshot) {
		auto_snap_fd = open(FUZZ_AUTO_PIPE, O_WRONLY | O_NONBLOCK);
		if (auto_snap_fd < 0) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "open %s failed, auto snapshot disabled", FUZZ_AUTO_PIPE);
		} else {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "auto snapshot enabled, notifying via %s", FUZZ_AUTO_PIPE);
		}
	}

	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "config loaded: %s", config_path);
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "mode: %d, debug: %s", config.mode, config.debug ? "true" : "false");
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "inst_ratio: %" PRIu32, config.inst_ratio);
	g_autoptr(GString) hex = g_string_new(NULL);
	for (size_t i = 0; i < config.instr_count; i++) {
		g_string_append_printf(hex, "0x%08" PRIx32 " ", config.instrs[i]);
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "entry instructions: %s", hex->str);
	g_log(
		LOG_DOMAIN,
		G_LOG_LEVEL_INFO,
		"entry addr: 0x%016" PRIx64 "  text_start: 0x%016" PRIx64 "  text_size: 0x%016" PRIx64,
		config.entry_addr,
		config.text_start,
		config.text_size
	);
}