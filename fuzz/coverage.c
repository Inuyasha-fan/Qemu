// 基于 QEMU 主循环的覆盖率采集模块
//
// 覆盖率记录逻辑从 TCG 插件移入主循环后，本模块负责：
//   - 解析 -fuzz 参数指定的 JSON 配置文件与目标 ELF
//   - 在 TB 执行出口记录覆盖率（由 accel/tcg/cpu-exec.c 调用）
//   - 内部使用 GHashTable 存储 TB 映射、链表存储执行 trace，
//     不再依赖固定大小的共享内存数组
//   - 维护 AFL 兼容的边覆盖 bitmap，测试结束后由 forkserver 拷贝到共享内存
//
// 三种识别模式（FuzzConfig.mode）：
//   - mode 0 ELF 指纹定位 + .text 物理范围过滤：解析 ELF 获得入口地址、.text 范围与入口指令，
//     运行时在新 TB 上指纹比对识别目标，计算 ASLR 偏移同步到 .text 范围；
//     仅在目标 .text 物理范围内记录覆盖率，ASID 变化（上下文轮换）时跟随更新
//   - mode 1 ELF 指纹定位 + 全范围覆盖：识别逻辑同 mode 0（同样计算偏移与 .text 物理范围），
//     但覆盖率不限制范围，全地址空间收集；仍通过 .text 物理范围捕获 ASID 变化
//   - mode 2 手动输入指纹字段：手动填入 entry_addr 与完整 entry_code，
//     识别出偏移时同步增加入口与 .text 范围，过滤方式同 mode 0
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
// edge bitmap：指针指向共享内存（fuzz_coverage_set_shm 绑定，实时可见，无需拷贝）
static uint8_t *edge_bitmap;
static uint32_t prev_loc_exec;

// 退出状态共享内存指针（程序退出/故障时实时写入，fuzzer 直接读取）
static uint32_t *shm_exit_status;

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
// 目标进程退出状态（waitpid 格式：正常退出为 exit_code<<8，信号终止为信号值）
static uint32_t exit_status;
// 疑似故障标记：用户模式 TLB 缺失后目标进程未再执行用户态代码（可能被内核判 SIGSEGV）。
// 需求分页成功时目标会立即恢复用户态执行，执行即清除此标记
static bool fault_pending;
static bool signal_pending;
// 疑似状态的预期恢复地址：内核处理异常后恢复用户态执行的位置
// （TLB 缺失=原 PC 重试；RI/CpU 等可仿真异常=PC+4；自杀信号=syscall 后续指令）。
// 目标用户态执行与该地址一致才算"内核已处理"，防止目标死亡后 ASID 被内核回收
// 复用于其他进程、其执行误清疑似状态导致崩溃漏报
static uint64_t pending_resume_pc;
// 目标 .text 物理范围起始（识别时由 phys-virt 位移与虚拟 .text 起始推导）
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
		} else if (g_strcmp0(key, "debug") == 0) {
			cfg->debug = (g_strcmp0(val, "true") == 0 || g_strcmp0(val, "1") == 0);
		} else if (g_strcmp0(key, "auto_snapshot") == 0) {
			cfg->auto_snapshot = (g_strcmp0(val, "true") == 0 || g_strcmp0(val, "1") == 0);
		} else if (g_strcmp0(key, "wait_snapshot_restore") == 0) {
			cfg->wait_snapshot_restore = (uint32_t)g_ascii_strtoull(val, NULL, 10);
		} else if (g_strcmp0(key, "wait_program_done") == 0) {
			cfg->wait_program_done = (uint32_t)g_ascii_strtoull(val, NULL, 10);
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

// 指纹比对：读取 guest 物理内存与入口指令字节比较，识别目标进程。
// 匹配成功即计算 ASLR 偏移（真实虚拟入口 - 解析出的静态入口），同步修正：
//   - .text 真实虚拟范围（仅输出参考，不参与过滤）
//   - .text 物理范围（内核映射 phys-virt 位移恒定，过滤/捕获 ASID 变化的稳定身份）
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

	// 无偏移时 offset 为 0：真实入口 == 静态入口，下面计算全部退化为原值
	uint64_t offset = virt_addr - config.entry_addr;
	uint64_t real_entry = config.entry_addr + offset;
	text_start += offset;
	// .text 物理范围：偏移与 phys-virt 位移同时作用于虚拟起始
	uint64_t text_phys_range_start = phys_addr - virt_addr + text_start;
	text_phys_start = text_phys_range_start;
	g_log(
		LOG_DOMAIN,
		G_LOG_LEVEL_INFO,
		"ASLR offset 0x%016" PRIx64 ", real entry virt 0x%016" PRIx64
		", text virt range: 0x%016" PRIx64 "-0x%016" PRIx64
		", text phys range: 0x%016" PRIx64 "-0x%016" PRIx64,
		offset,
		real_entry,
		text_start,
		text_start + text_size,
		text_phys_start,
		text_phys_start + text_size
	);

	// 自动保存快照模式：通知 forkserver 在目标入口识别后保存快照
	if (auto_snap_fd >= 0) {
		unsigned char notify = 0x01;
		if (write(auto_snap_fd, &notify, 1) != 1) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "notify forkserver auto save failed");
		}
	}
}

// 记录一个已执行 TB 的覆盖率（主循环 TB 执行出口调用）
void fuzz_coverage_record_tb(uint64_t virt_addr, uint64_t phys_addr, uint32_t insn_count, uint64_t asid, bool user_mode) {
	g_mutex_lock(&lock);

	// 目标进程用户态在预期恢复地址重新执行：上一处疑似故障/信号已被内核处理
	// （需求分页、RI/CpU 仿真等），非致命。回写超时哨兵——程序仍存活，
	// 真实状态由之后的退出/信号/新故障覆盖。
	// 按地址精确确认：目标死亡后 ASID 可能被内核回收复用于其他进程，
	// 仅凭 ASID 匹配会误清疑似状态；恢复地址是内核处理路径的确定性结果
	if ((fault_pending || signal_pending) && user_mode && target_found &&
	    asid == target_asid && virt_addr == pending_resume_pc) {
		fault_pending = false;
		signal_pending = false;
		exit_status = 0;
		if (shm_exit_status) {
			*shm_exit_status = FUZZ_EXIT_TIMEOUT;
		}
	}

	// 目标未识别：每个新 TB 上尝试指纹比对（mode 0 虚入口偏移、mode 1 全范围扫描、
	// mode 2 手动指纹都需要先定位真实入口；比对失败则本 TB 不参与）
	if (!target_found) {
		// 系统模式下 ASID 0 为内核代码，不参与目标识别
		if (asid == 0) {
			g_mutex_unlock(&lock);
			return;
		}
		if (phys_addr != (uint64_t)-1) {
			fuzz_identify(virt_addr, phys_addr, asid);
		}
		if (!target_found) {
			g_mutex_unlock(&lock);
			return;
		}
	}

	// 识别成功后：物理范围判定 + ASID 跟随。
	// .text 物理范围是目标二进制的稳定身份（内核映射 phys-virt 位移恒定）；
	// 范围内 ASID 变化说明目标上下文轮换/切换，全局 ASID 跟随更新。
	// 物理范围之外（mode 1 全范围收集时）只可能是 ASID 已失去目标身份，不重复更新。
	bool in_text = phys_addr >= text_phys_start && phys_addr <= text_phys_start + text_size;
	if (in_text && user_mode && asid != target_asid) {
		g_log(
			LOG_DOMAIN,
			G_LOG_LEVEL_INFO,
			"target asid re-pinned: 0x%02" PRIx64 " -> 0x%02" PRIx64 " (text tb 0x%" PRIx64 " phys 0x%" PRIx64 ")",
			target_asid,
			asid,
			virt_addr,
			phys_addr
		);
		target_asid = asid;
	}

	// 覆盖率捕获范围：mode 0/2 仅记录 .text 物理范围内的 TB；
	// mode 1 全范围收集（仍通过物理范围跟随 ASID）
	if (asid != target_asid || (config.mode != 1 && !in_text)) {
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

// 各轮等待配置 getter（forkserver 控制 0x02 ack 前 / 0x03 handler 的休眠时长）
uint32_t fuzz_coverage_wait_snapshot_restore(void) {
	return config.wait_snapshot_restore;
}

uint32_t fuzz_coverage_wait_program_done(void) {
	return config.wait_program_done;
}

// 记录目标进程退出（syscall 异常时由 tlb_helper 调用）：仅捕获已识别目标的退出码，
// waitpid 格式 status = (exit_code & 0xff) << 8
void fuzz_coverage_record_exit(uint64_t asid, uint32_t exit_code) {
	g_mutex_lock(&lock);
	if (target_found && asid == target_asid) {
		exit_status = (exit_code & 0xff) << 8;
		if (shm_exit_status) {
			*shm_exit_status = exit_status;
		}
	}
	g_mutex_unlock(&lock);
}

// 记录目标进程被信号终止（waitpid 格式 status 直接存信号值，WIFSIGNALED 为真）
// 延迟确认：先标记疑似信号并写入，目标用户态在 pc+4 重新执行说明内核已处理，回写哨兵；
// 若进程被内核杀死，不再有用户态执行，疑似状态保持到本轮 dump 上报
void fuzz_coverage_record_signal(uint64_t asid, uint32_t sig, uint64_t pc) {
	g_mutex_lock(&lock);
	if (target_found && asid == target_asid) {
		signal_pending = true;
		pending_resume_pc = pc + 4;
		exit_status = sig;
		if (shm_exit_status) {
			*shm_exit_status = exit_status;
		}
	}
	g_mutex_unlock(&lock);
}

// 记录疑似故障（用户模式 TLB 缺失）：内核可能需求分页返回（非致命），也可能判 SIGSEGV 杀进程
// 立即写疑似状态 11 到共享内存；需求分页成功后目标在原 PC 重试执行，record_tb 确认后清除
void fuzz_coverage_record_fault(uint64_t asid, uint64_t pc) {
	g_mutex_lock(&lock);
	if (target_found && asid == target_asid) {
		fault_pending = true;
		pending_resume_pc = pc;
		exit_status = 11;
		if (shm_exit_status) {
			*shm_exit_status = exit_status;
		}
	}
	g_mutex_unlock(&lock);
}

// 绑定共享内存作为实时载体：edge bitmap 直接指向共享内存，退出状态置为超时哨兵
void fuzz_coverage_set_shm(uint8_t *edge_map, uint32_t *exit_status_shm) {
	g_mutex_lock(&lock);
	edge_bitmap = edge_map;
	shm_exit_status = exit_status_shm;
	*shm_exit_status = FUZZ_EXIT_TIMEOUT;
	g_mutex_unlock(&lock);
}

// 重置本轮测试的覆盖率数据（恢复为保存快照时的状态，无备份时全清零）
void fuzz_coverage_reset(void) {
	g_mutex_lock(&lock);
	// 每轮快照恢复后目标进程重新执行，退出状态必须复原为超时哨兵（真实状态由程序退出时写入）
	exit_status = 0;
	fault_pending = false;
	signal_pending = false;
	pending_resume_pc = 0;
	if (shm_exit_status) {
		*shm_exit_status = FUZZ_EXIT_TIMEOUT;
	}
	g_hash_table_destroy(tb_map);
	free_trace(trace_head);
	trace_head = NULL;
	trace_tail = NULL;
	trace_count = 0;

	if (has_backup) {
		tb_map = copy_tb_map(backup_tb_map);
		trace_head = copy_trace(backup_trace_head, &trace_tail, &trace_count);
		memcpy(edge_bitmap, backup_edge_bitmap, EDGE_MAP_SIZE);
		prev_loc_exec = backup_prev_loc_exec;
	} else {
		tb_map = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
		memset(edge_bitmap, 0, EDGE_MAP_SIZE);
		prev_loc_exec = 0;
	}
	g_mutex_unlock(&lock);
}

// 输出覆盖率信息，fuzz_count 为第几次 fuzz 的覆盖率，快照刚保存未开始 fuzz 时传 0
void fuzz_coverage_dump(uint64_t fuzz_count) {
	g_mutex_lock(&lock);

	if (fuzz_count == 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "coverage captured at snapshot save, before any fuzz round");
	} else {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "coverage after fuzz round %" PRIu64, fuzz_count);
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

	// 目标退出状态（实时共享内存中的当前值，哨兵=程序本轮未退出）
	uint32_t st = (shm_exit_status ? *shm_exit_status : exit_status);
	if (st == FUZZ_EXIT_TIMEOUT) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "exit status: 0x%08x (timeout sentinel, program did not exit)", st);
	} else if (st & 0x7f) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "exit status: 0x%08x (signal %u)", st, st & 0x7f);
	} else {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "exit status: 0x%08x (exit code %u)", st, st >> 8);
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

	// 模式 0/1：ELF 指纹自动定位（忽略手填地址字段，入口/.text 由 ELF 解析得出）
	if (config.mode == 0 || config.mode == 1) {
		if (!config.elf_path || config.elf_path[0] == '\0') {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mode %d requires elf_path in config", config.mode);
			return;
		}
		if (!parse_elf(config.elf_path, &config)) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "failed to parse ELF: %s", config.elf_path);
			return;
		}
	}

	// 模式 2：手动输入指纹字段，必须提供完整 entry_code
	if (config.mode == 2 && config.instr_count != ENTRY_INSTR_COUNT) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mode 2 requires entry_code with %d instructions", ENTRY_INSTR_COUNT);
		return;
	}

	if (config.mode < 0 || config.mode > 2) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "invalid mode %d, must be 0-2", config.mode);
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