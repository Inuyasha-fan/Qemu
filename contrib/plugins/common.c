#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <glib.h>
#include <qemu-plugin.h>

#include "elf.h"
#include "common.h"

gint cmp_virt_addr(gconstpointer a, gconstpointer b) {
	const SortedEntry *ea = a;
	const SortedEntry *eb = b;
	if (ea->virt_addr < eb->virt_addr) return -1;
	if (ea->virt_addr > eb->virt_addr) return 1;
	return 0;
}

static inline uint16_t be16(uint16_t x) { return __builtin_bswap16(x); }
static inline uint32_t be32(uint32_t x) { return __builtin_bswap32(x); }
static inline uint64_t be64(uint64_t x) { return __builtin_bswap64(x); }

void log_handler(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer fp) {
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

uint64_t coverage_hash(uint64_t vaddr, uint64_t icount, uint64_t asid, uint64_t paddr) {
	uint64_t h = vaddr;
	h ^= icount;
	h = (h << 31) | (h >> 33);
	h ^= asid;
	h = ~h;
	h = (h << 27) | (h >> 37);
	h ^= paddr;
	h &= 0x7fffffffffffffffULL;
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53ULL;
	h ^= h >> 33;
	return h;
}

void instrs_to_bytes(const ElfEntryInfo *info, uint8_t buf[ENTRY_INSTR_COUNT * 4]) {
	for (size_t i = 0; i < ENTRY_INSTR_COUNT; i++) {
		uint32_t v = info->instrs[i];
		buf[i * 4] = (v >> 24) & 0xff;
		buf[i * 4 + 1] = (v >> 16) & 0xff;
		buf[i * 4 + 2] = (v >> 8) & 0xff;
		buf[i * 4 + 3] = v & 0xff;
	}
}

static void bytes_to_instrs(uint8_t *buf, size_t len, ElfEntryInfo *info) {
	size_t n = len > ENTRY_INSTR_COUNT * 4 ? ENTRY_INSTR_COUNT * 4 : len;
	info->instr_count = n / 4;
	for (size_t i = 0; i < n; i += 4) {
		info->instrs[i / 4] =
			((uint32_t)buf[i] << 24) |
			((uint32_t)buf[i + 1] << 16) |
			((uint32_t)buf[i + 2] << 8) |
			(uint32_t)buf[i + 3];
	}
}

// 解析 JSON 配置文件，返回 mode 及 ELF 路径，剩余字段填入 info
ParseResult parse_config(const char *path, ElfEntryInfo *info, char **elf_path_out, int *mode_out) {
	g_autofree char *content = NULL;
	gsize len;
	if (!g_file_get_contents(path, &content, &len, NULL)) {
		return PARSE_ERR_OPEN;
	}

	memset(info, 0, sizeof(*info));
	if (elf_path_out) {
		*elf_path_out = NULL;
	}
	if (mode_out) {
		*mode_out = -1;
	}

	// 简化 JSON 解析：按行处理 key-value 对
	g_auto(GStrv) lines = g_strsplit(content, "\n", 0);
	int list_count = 0;
	gboolean in_list = FALSE;

	for (int i = 0; lines[i]; i++) {
		g_autofree char *raw_line = g_strdup(lines[i]);
		char *line = g_strstrip(raw_line);

		// 跳过空行、注释和纯符号行
		if (line[0] == '\0' || line[0] == '/' || line[0] == '#'
			|| line[0] == '{' || line[0] == '}') {
			continue;
		}

		// 列表项处理
		if (in_list) {
			if (line[0] == '"') {
				const char *val = line + 1;
				const char *end = strchr(val, '"');
				if (end) {
					g_autofree char *v = g_strndup(val, end - val);
					if (list_count < ENTRY_INSTR_COUNT) {
						info->instrs[list_count] = (uint32_t)g_ascii_strtoull(v, NULL, 16);
						info->instr_count = list_count + 1;
					}
					list_count++;
				}
				continue;
			}
			in_list = FALSE;
		}

		// 解析 key: value 对
		g_auto(GStrv) kv = g_strsplit(line, ":", 2);
		if (!kv[0] || !kv[1]) {
			continue;
		}
		g_autofree char *key_raw = g_strdup(kv[0]);
		g_autofree char *val_raw = g_strdup(kv[1]);
		char *key = g_strstrip(key_raw);
		char *val = g_strstrip(val_raw);

		// 去除 key 的引号
		if (key[0] == '"') {
			key++;
		}
		size_t klen = strlen(key);
		if (klen > 1 && key[klen - 1] == '"') {
			key[klen - 1] = '\0';
		}

		// 去除 val 的引号和尾逗号
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
			if (mode_out) {
				*mode_out = (int)g_ascii_strtoull(val, NULL, 10);
			}
		} else if (g_strcmp0(key, "elf_path") == 0) {
			if (elf_path_out && val[0] != '\0') {
				*elf_path_out = g_strdup(val);
			}
		} else if (g_strcmp0(key, "entry_addr") == 0) {
			if (val[0] != '\0') {
				info->addr = g_ascii_strtoull(val, NULL, 16);
			}
		} else if (g_strcmp0(key, "text_start") == 0) {
			if (val[0] != '\0') {
				info->text_start = g_ascii_strtoull(val, NULL, 16);
			}
		} else if (g_strcmp0(key, "text_size") == 0) {
			if (val[0] != '\0') {
				info->text_size = g_ascii_strtoull(val, NULL, 16);
			}
		} else if (g_strcmp0(key, "inst_ratio") == 0) {
			info->inst_ratio = (uint32_t)g_ascii_strtoull(val, NULL, 10);
		} else if (g_strcmp0(key, "debug") == 0) {
			info->debug = (g_strcmp0(val, "true") == 0 || g_strcmp0(val, "1") == 0);
		} else if (g_strcmp0(key, "entry_code") == 0) {
			in_list = TRUE;
			list_count = 0;
		}
	}

	return PARSE_OK;
}

ParseResult parse_elf(const char *path, ElfEntryInfo *info) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return PARSE_ERR_OPEN;
	}

	uint8_t e_ident[EI_NIDENT];
	if (read(fd, e_ident, EI_NIDENT) != EI_NIDENT) {
		close(fd);
		return PARSE_ERR_READ;
	}

	if (e_ident[EI_CLASS] != ELFCLASS32 && e_ident[EI_CLASS] != ELFCLASS64) {
		close(fd);
		return PARSE_ERR_CLASS;
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

	// 查找 _start 符号
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

	info->addr = start_addr;

	// 找 .text 节
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
			info->text_start = sh_addr;
			info->text_size = sh_size;
			break;
		}
	}

	// 读入口处机器码
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

		if (p_type == PT_LOAD && start_addr >= p_vaddr &&
			start_addr < p_vaddr + p_filesz) {
			lseek(fd, p_offset + (start_addr - p_vaddr), SEEK_SET);
			uint8_t code_buf[ENTRY_INSTR_COUNT * 4];
			ssize_t n = read(fd, code_buf, sizeof(code_buf));
			bytes_to_instrs(code_buf, n > 0 ? (size_t)n : 0, info);
			break;
		}
	}

	close(fd);
	return PARSE_OK;
}

uint64_t try_identify_target(const ElfEntryInfo *info, uint64_t asid, uint64_t phys) {
	if (info->instr_count != ENTRY_INSTR_COUNT) {
		return (uint64_t)-1;
	}

	uint8_t expected[ENTRY_INSTR_COUNT * 4];
	instrs_to_bytes(info, expected);

	uint8_t buf[ENTRY_INSTR_COUNT * 4];
	ssize_t n = qemu_plugin_read_phys_memory(phys, buf, sizeof(buf));
	if (n != (ssize_t)sizeof(buf)) {
		return (uint64_t)-1;
	}
	if (memcmp(buf, expected, sizeof(buf)) != 0) {
		return (uint64_t)-1;
	}

	return asid;
}

// 深度拷贝 coverage_map
GHashTable *deep_copy_coverage_map(GHashTable *src) {
	GHashTable *dst = g_hash_table_new(NULL, g_direct_equal);
	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, src);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		Coverage *src_cnt = (Coverage *)value;
		Coverage *dst_cnt = g_new0(Coverage, 1);
		*dst_cnt = *src_cnt;
		g_hash_table_insert(dst, key, dst_cnt);
	}
	return dst;
}

// 初始化共享内存，返回共享内存指针
uint8_t *fuzz_init_shm(void) {
	int shmid = shmget(FUZZ_SHM_KEY, EDGE_MAP_SIZE, IPC_CREAT | 0666);
	if (shmid < 0) {
		g_warning("shmget failed");
		return NULL;
	}
	uint8_t *ptr = (uint8_t *)shmat(shmid, NULL, 0);
	if (ptr == (void *)-1) {
		g_warning("shmat failed");
		return NULL;
	}
	memset(ptr, 0, EDGE_MAP_SIZE);
	g_info("shared memory initialized at key 0x%x", FUZZ_SHM_KEY);
	return ptr;
}
