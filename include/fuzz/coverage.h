#ifndef FUZZ_COVERAGE_H
#define FUZZ_COVERAGE_H

#include <stdbool.h>
#include <stdint.h>
#include <glib.h>

// 边覆盖 bitmap 大小（与 AFLNet 的 MAP_SIZE 保持一致）
#define EDGE_MAP_SIZE 65536
// 边覆盖共享内存 key（仅供 AFLNet 读取）
#define FUZZ_SHM_EDGE_KEY 0x2000
#define FUZZ_SHM_EDGE_SIZE sizeof(uint8_t[EDGE_MAP_SIZE])

// 入口指纹指令条数
#define ENTRY_INSTR_COUNT 8

// 自动保存快照通知管道（coverage 识别到目标入口后写入，forkserver 读取并保存快照）
#define FUZZ_AUTO_PIPE "/tmp/qemu_fuzz_auto"

// 日志域
#ifndef LOG_DOMAIN
#define LOG_DOMAIN "coverage"
#endif

// TB 映射表条目
typedef struct {
	uint64_t virt_addr;  // hash key
	uint64_t phys_addr;
	uint64_t exec_count;
	uint64_t insn_count;
} CoverageEntry;

// 执行 trace 链表节点（数组顺序即执行顺序）
typedef struct FuzzTraceEntry {
	uint64_t virt_addr;
	uint32_t cur_loc;
	uint32_t exec_count;
	struct FuzzTraceEntry *next;
} FuzzTraceEntry;

// 覆盖率配置（由 -fuzz 参数指定的 JSON 文件解析而来）
typedef struct {
	int mode;                   // 0: 已知入口+ELF 指纹  1: ASLR+ELF 自动定位
	                            // 2: ASLR 全范围扫描     3: 手动输入指纹字段
	bool debug;                 // 是否输出 debug 日志
	bool auto_snapshot;         // 识别到目标入口后是否自动保存快照（false 时由 fuzzer 控制）
	bool cov_block;             // 收集 block 覆盖率（TB 映射表）
	bool cov_edge;              // 收集 edge 覆盖率（边 bitmap）
	bool cov_trace;             // 收集 trace 覆盖率（执行 trace 链表）
	char *elf_path;             // 目标 ELF 路径
	uint64_t entry_addr;        // 入口函数地址，0 表示未知
	uint64_t text_start;        // .text 起始地址，0 表示不过滤
	uint64_t text_size;         // .text 大小
	uint32_t inst_ratio;        // 边覆盖采样比例，0 表示 100%
	uint32_t instrs[ENTRY_INSTR_COUNT];  // 入口指令，大端 uint32_t
	size_t instr_count;         // 入口指令条数
} FuzzConfig;

// 初始化覆盖率模块（解析配置、ELF，初始化数据结构）
void fuzz_coverage_init(const char *config_path);
// 记录一个已执行 TB 的覆盖率（由主循环 TB 执行出口调用）
void fuzz_coverage_record_tb(uint64_t virt_addr, uint64_t phys_addr, uint32_t insn_count, uint64_t asid);
// 是否开启自动保存快照（识别到目标入口后自动保存）
bool fuzz_coverage_auto_snapshot(void);
// 将当前覆盖率状态深拷贝为备份（save_snapshot 成功后调用）
void fuzz_coverage_backup(void);
// 重置本轮测试的覆盖率数据（恢复为保存快照时的状态，无备份时全清零）
void fuzz_coverage_reset(void);
// 将内部 edge bitmap 拷贝到共享内存供 AFLNet 读取
void fuzz_coverage_copy_edge_map(uint8_t *dst);
// 输出覆盖率信息（条目级日志受配置 debug 控制）
void fuzz_coverage_dump(void);

#endif
