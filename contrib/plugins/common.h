#ifndef COVERAGE_COMMON_H
#define COVERAGE_COMMON_H

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#define ENTRY_INSTR_COUNT 8
#define EDGE_MAP_SIZE     65536

// 插件通知主线程的管道路径
#define FUZZ_NOTIFY_PIPE "/tmp/qemu_fuzz_notify"
// 共享内存 key
#define FUZZ_SHM_KEY 0x2000

typedef struct {
	uint64_t phys_addr;   // 物理地址，-1 表示未映射
	uint64_t trans_count; // 翻译次数
	uint64_t exec_count;  // 执行次数
	uint64_t insn_count;  // 指令条数
} Coverage;

typedef struct {
	uint64_t virt_addr;
	Coverage *rec;
} SortedEntry;

typedef struct EdgeTrace {
	uint64_t virt_addr;
	uint32_t cur_loc;
	uint32_t exec_count;
	struct EdgeTrace *next;
} EdgeTrace;

typedef struct {
	uint64_t addr;                              // 入口函数地址，0 表示未知
	uint64_t text_start;                        // .text 起始地址，0 表示不过滤
	uint64_t text_size;                         // .text 大小
	uint32_t instrs[ENTRY_INSTR_COUNT];         // 入口指令，大端 uint32_t
	size_t instr_count;                         // 入口指令条数
	uint32_t inst_ratio;                        // 边覆盖采样比例，0 表示 100%
	bool debug;                                  // 是否输出 g_debug 日志
	bool fuzz;                                   // 是否启用 fuzz 模式
} ElfEntryInfo;

typedef enum {
	PARSE_OK = 0,
	PARSE_ERR_OPEN,
	PARSE_ERR_READ,
	PARSE_ERR_CLASS,
} ParseResult;

gint cmp_virt_addr(gconstpointer a, gconstpointer b);

void log_handler(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer fp);

ParseResult parse_elf(const char *path, ElfEntryInfo *info);

ParseResult parse_config(const char *path, ElfEntryInfo *info, char **elf_path_out, int *mode_out);

void instrs_to_bytes(const ElfEntryInfo *info, uint8_t buf[ENTRY_INSTR_COUNT * 4]);

uint64_t try_identify_target(const ElfEntryInfo *info, uint64_t asid, uint64_t phys);

// fuzz 相关函数
// 深度拷贝 coverage_map
GHashTable *deep_copy_coverage_map(GHashTable *src);

// 初始化共享内存，返回共享内存指针
uint8_t *fuzz_init_shm(void);

#endif
