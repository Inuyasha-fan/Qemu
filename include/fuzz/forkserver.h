#ifndef FUZZ_FORKSERVER_H
#define FUZZ_FORKSERVER_H

#include <stdbool.h>
#include <stdint.h>
#include <glib.h>

// 边覆盖 map 大小
#define EDGE_MAP_SIZE 65536
// 最大 TB 条目数
#define FUZZ_MAX_TB_ENTRIES 16384
// 最大 trace 条目数
#define FUZZ_MAX_TRACE_ENTRIES 16384

// 共享内存 key（三段独立）
#define FUZZ_SHM_EDGE_KEY  0x2000  // edge_map
#define FUZZ_SHM_COV_KEY   0x2001  // coverage
#define FUZZ_SHM_TRACE_KEY 0x2002  // trace + prev_loc_exec + trace_idx

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

// AFLNet forkserver 控制管道路径
#define FUZZ_CTL_PIPE "/tmp/qemu_fuzz_ctl"
// AFLNet 状态管道路径
#define FUZZ_ST_PIPE "/tmp/qemu_fuzz_st"
// 插件通知主线程的管道路径
#define FUZZ_NOTIFY_PIPE "/tmp/qemu_fuzz_notify"
// 快照名称
#define FUZZ_SNAPSHOT_NAME "fuzz_snapshot"

// 日志域
#define LOG_DOMAIN "forkserver"

// 函数声明
void fuzz_set_enabled(bool enabled);
void fuzz_set_debug(bool enabled);

#endif // FUZZ_FORKSERVER_H
