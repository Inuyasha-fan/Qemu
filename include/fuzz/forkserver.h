#ifndef FUZZ_FORKSERVER_H
#define FUZZ_FORKSERVER_H

#include <stdbool.h>
#include <stdint.h>
#include <glib.h>

// AFLNet forkserver 控制管道路径
#define FUZZ_CTL_PIPE "/tmp/qemu_fuzz_ctl"
// AFLNet 状态管道路径
#define FUZZ_ST_PIPE "/tmp/qemu_fuzz_st"
// 插件通知主线程的管道路径
#define FUZZ_NOTIFY_PIPE "/tmp/qemu_fuzz_notify"

// 函数声明
void fuzz_set_enabled(bool enabled);

#endif // FUZZ_FORKSERVER_H
