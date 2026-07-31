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
// 共享内存 key
#define FUZZ_SHM_KEY 0x2000
// 共享内存大小 (64KB，与 AFL bitmap 大小一致)
#define FUZZ_SHM_SIZE 65536

// 函数声明
void fuzz_set_enabled(bool enabled);
void fuzz_forkserver_loop(void);

#endif // FUZZ_FORKSERVER_H
