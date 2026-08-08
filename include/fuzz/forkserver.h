#ifndef FUZZ_FORKSERVER_H
#define FUZZ_FORKSERVER_H

#include <stdbool.h>

// AFLNet forkserver 控制管道路径
#define FUZZ_CTL_PIPE "/tmp/qemu_fuzz_ctl"
// AFLNet 状态管道路径
#define FUZZ_ST_PIPE "/tmp/qemu_fuzz_st"
// 快照名称
#define FUZZ_SNAPSHOT_NAME "fuzz_snapshot"

// 日志域
#ifndef LOG_DOMAIN
#define LOG_DOMAIN "forkserver"
#endif

// 函数声明
void fuzz_set_enabled(bool enabled);
// fuzz 模式是否已启用（由 -fuzz 参数触发）
bool fuzz_enabled(void);

#endif // FUZZ_FORKSERVER_H
