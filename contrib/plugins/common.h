#ifndef COVERAGE_COMMON_H
#define COVERAGE_COMMON_H

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#define ENTRY_INSTR_COUNT 8
#define EDGE_MAP_SIZE     65536
#define FUZZ_MAX_TB_ENTRIES 16384
#define FUZZ_MAX_TRACE_ENTRIES 16384

// 共享内存 key（三段独立）
#define FUZZ_SHM_EDGE_KEY  0x2000
#define FUZZ_SHM_COV_KEY   0x2001
#define FUZZ_SHM_TRACE_KEY 0x2002

// 日志域
#define LOG_DOMAIN "coverage"

// 插件通知主线程的管道路径
#define FUZZ_NOTIFY_PIPE "/tmp/qemu_fuzz_notify"

// 共享内存中的 coverage 条目
typedef struct {
	uint64_t virt_addr;  // hash key, 0 表示空槽
	uint64_t phys_addr;
	uint64_t trans_count;
	uint64_t exec_count;
	uint64_t insn_count;
} ShmCoverageEntry;

// 共享内存中的 trace 条目（数组顺序即执行顺序）
typedef struct {
	uint64_t virt_addr;
	uint32_t cur_loc;
	uint32_t exec_count;
} ShmTraceEntry;

// trace 共享内存布局
typedef struct {
	uint32_t prev_loc_exec;
	uint32_t trace_idx;
	ShmTraceEntry entries[FUZZ_MAX_TRACE_ENTRIES];
} FuzzShmTrace;

// 覆盖率共享内存布局
typedef struct {
	ShmCoverageEntry entries[FUZZ_MAX_TB_ENTRIES];
} FuzzShmCov;

// 各段共享内存大小
#define FUZZ_SHM_EDGE_SIZE  sizeof(uint8_t[EDGE_MAP_SIZE])
#define FUZZ_SHM_COV_SIZE   sizeof(FuzzShmCov)
#define FUZZ_SHM_TRACE_SIZE sizeof(FuzzShmTrace)

typedef struct {
	uint64_t addr;                              // 入口函数地址，0 表示未知
	uint64_t text_start;                        // .text 起始地址，0 表示不过滤
	uint64_t text_size;                         // .text 大小
	uint32_t instrs[ENTRY_INSTR_COUNT];         // 入口指令，大端 uint32_t
	size_t instr_count;                         // 入口指令条数
	uint32_t inst_ratio;                        // 边覆盖采样比例，0 表示 100%
	bool debug;                                  // 是否输出 g_debug 日志
} ElfEntryInfo;

typedef enum {
	PARSE_OK = 0,
	PARSE_ERR_OPEN,
	PARSE_ERR_READ,
	PARSE_ERR_CLASS,
} ParseResult;

void log_handler(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer fp);

ParseResult parse_elf(const char *path, ElfEntryInfo *info);

ParseResult parse_config(const char *path, ElfEntryInfo *info, char **elf_path_out, int *mode_out);

void instrs_to_bytes(const ElfEntryInfo *info, uint8_t buf[ENTRY_INSTR_COUNT * 4]);

uint64_t try_identify_target(const ElfEntryInfo *info, uint64_t asid, uint64_t phys);

// fuzz 辅助函数
// 初始化三段共享内存，edge_map/cov/trace 指针写入参数，失败返回 -1
int fuzz_init_shm(uint8_t **edge_out, FuzzShmCov **cov_out, FuzzShmTrace **trace_out);
// 在共享内存 coverage 表中查找
ShmCoverageEntry *shm_coverage_lookup(FuzzShmCov *cov, uint64_t virt_addr);
// 在共享内存 coverage 表中插入
ShmCoverageEntry *shm_coverage_insert(FuzzShmCov *cov, uint64_t virt_addr);
// 统计 edge 数量
uint32_t shm_edge_count(uint8_t *edge_map);

#endif
