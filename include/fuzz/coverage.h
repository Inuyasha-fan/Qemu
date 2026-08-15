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
// 退出状态共享内存 key（waitpid 格式 status，仅供 AFLNet 读取）
#define FUZZ_SHM_EXIT_KEY 0x2001
#define FUZZ_SHM_EXIT_SIZE sizeof(uint32_t)
// 退出状态哨兵值：快速恢复后程序未退出时为该值，fuzzer 读到即视为本轮超时
// （须与 Aflnet/afl-fuzz.c 的 FUZZ_EXIT_TIMEOUT 保持一致，且不能是合法 waitpid 状态）
#define FUZZ_EXIT_TIMEOUT 0xDEADBEEF

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
	uint64_t asid;       // 所属进程 ASID
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
	int mode;                   // 0: ELF 指纹 + .text 物理范围过滤
	                            // 1: ELF 指纹 + 全范围收集（物理范围仅跟随 ASID）
	                            // 2: 手动输入指纹字段
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
	uint32_t wait_snapshot_restore;      // 快照恢复等待（毫秒），0x02 ack 前休眠
	uint32_t wait_program_done;          // 程序处理等待（毫秒），0x03 handler 休眠
} FuzzConfig;

// 初始化覆盖率模块（解析配置、ELF，初始化数据结构）
void fuzz_coverage_init(const char *config_path);
// 记录一个已执行 TB 的覆盖率（由主循环 TB 执行出口调用，user_mode 为执行时的 guest 用户态标志）
void fuzz_coverage_record_tb(uint64_t virt_addr, uint64_t phys_addr, uint32_t insn_count, uint64_t asid, bool user_mode);
// 记录目标进程退出（syscall 异常时由 tlb_helper 调用，exit_code 为 a0）
void fuzz_coverage_record_exit(uint64_t asid, uint32_t exit_code);
// 记录目标进程被信号终止（用户模式致命异常/自杀信号，sig 为信号值，pc 为异常时 PC）。
// 延迟确认：内核可能仿真异常指令后恢复执行（见 coverage.c 说明）
void fuzz_coverage_record_signal(uint64_t asid, uint32_t sig, uint64_t pc);
// 记录目标进程疑似故障（用户模式 TLB 缺失，内核可能需求分页或判 SIGSEGV，pc 为缺失地址）
void fuzz_coverage_record_fault(uint64_t asid, uint64_t pc);
// 绑定实时共享内存：edge bitmap 直接用共享内存作为内部载体，退出状态每轮重置为哨兵值、
// 程序退出时写入真实状态（由 forkserver 启动时调用）
void fuzz_coverage_set_shm(uint8_t *edge_map, uint32_t *exit_status);
// 是否开启自动保存快照（识别到目标入口后自动保存）
bool fuzz_coverage_auto_snapshot(void);
// 将当前覆盖率状态深拷贝为备份（save_snapshot 成功后调用）
void fuzz_coverage_backup(void);
// 重置本轮测试的覆盖率数据（恢复为保存快照时的状态，无备份时全清零）
void fuzz_coverage_reset(void);
// 输出覆盖率信息（fuzz_count 为第几次 fuzz 轮次，快照刚保存未开始 fuzz 时传 0）
void fuzz_coverage_dump(uint64_t fuzz_count);
// 各轮等待配置（毫秒）：0x02 ack 前的快照恢复等待、0x03 handler 的程序处理等待
uint32_t fuzz_coverage_wait_snapshot_restore(void);
uint32_t fuzz_coverage_wait_program_done(void);

#endif
