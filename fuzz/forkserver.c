// AFLNet 快照型 forkserver
//
// 与 AFLNet 通过命名管道通信，通过控制管道接收命令：
//   - 0x01：保存快照（由用户手动触发，目标程序已处于稳定状态）
//   - 0x02：执行一轮测试（加载快照、重置覆盖率、恢复虚拟机运行）
//   - 0x03：结束本轮测试（由 fuzzer 写入，触发拷贝到共享内存）
// 每个命令处理完成后向状态管道写入 status（1 正常，2 错误），fuzzer 阻塞读取后才能发送下一条命令
// 每轮测试的起止由命令 0x01/0x03 驱动，不使用任何计时器

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/timer.h"
#include "sysemu/cpus.h"
#include "sysemu/runstate.h"
#include "migration/snapshot.h"
#include "fuzz/forkserver.h"
#include "fuzz/coverage.h"

#include <inttypes.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// 内部变量
static FILE *log_fp;
static const char *log_path = "Logs/forkserver.log";
static int fuzz_ctl_fd = -1;
static int fuzz_st_fd = -1;
static int fuzz_auto_fd = -1;
static int fuzz_forkserver_count = 0;
static bool fuzz_fs_enabled = false;

// 延迟发送 status 的定时器（等待快照恢复 / 等待程序处理，不能阻塞主循环）
static QEMUTimer *fuzz_restore_timer;
static QEMUTimer *fuzz_copy_timer;

// 共享内存（边覆盖 bitmap 供 AFLNet 读取，退出状态供 AFLNet 读取）
static uint8_t *shm_edge_map = NULL;
static uint32_t *shm_exit_status = NULL;

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

// 初始化日志
static void fuzz_init_log(void) {
	g_mkdir_with_parents("Logs", 0755);
	log_fp = fopen(log_path, "w");
	if (log_fp) {
		g_log_set_handler(LOG_DOMAIN, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL, log_handler, log_fp);
	}
}

// 创建边覆盖共享内存（key 0x2000，与 AFLNet 约定一致）
static void fuzz_create_shm(void) {
	int shmid = shmget(FUZZ_SHM_EDGE_KEY, FUZZ_SHM_EDGE_SIZE, IPC_CREAT | 0666);
	if (shmid < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "shmget failed for key 0x%x", FUZZ_SHM_EDGE_KEY);
		return;
	}
	shm_edge_map = (uint8_t *)shmat(shmid, NULL, 0);
	if (shm_edge_map == (void *)-1) {
		shm_edge_map = NULL;
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "shmat failed for key 0x%x", FUZZ_SHM_EDGE_KEY);
		return;
	}
	memset(shm_edge_map, 0, FUZZ_SHM_EDGE_SIZE);
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "edge map shared memory created at key 0x%x", FUZZ_SHM_EDGE_KEY);
}

// 创建退出状态共享内存（key 0x2001，与 AFLNet 约定一致）
static void fuzz_create_exit_shm(void) {
	int shmid = shmget(FUZZ_SHM_EXIT_KEY, FUZZ_SHM_EXIT_SIZE, IPC_CREAT | 0666);
	if (shmid < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "shmget failed for key 0x%x", FUZZ_SHM_EXIT_KEY);
		return;
	}
	shm_exit_status = (uint32_t *)shmat(shmid, NULL, 0);
	if (shm_exit_status == (void *)-1) {
		shm_exit_status = NULL;
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "shmat failed for key 0x%x", FUZZ_SHM_EXIT_KEY);
		return;
	}
	*shm_exit_status = 0;
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "exit status shared memory created at key 0x%x", FUZZ_SHM_EXIT_KEY);
}

// 初始化控制/状态管道（非阻塞打开，不阻塞 QEMU 启动）
// 返回 0 成功，-1 失败
static int fuzz_init_pipes(void) {
	unlink(FUZZ_CTL_PIPE);
	if (mkfifo(FUZZ_CTL_PIPE, 0666) < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mkfifo %s failed", FUZZ_CTL_PIPE);
		return -1;
	}
	unlink(FUZZ_ST_PIPE);
	if (mkfifo(FUZZ_ST_PIPE, 0666) < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mkfifo %s failed", FUZZ_ST_PIPE);
		return -1;
	}

	// 控制管道读端以 O_RDONLY 非阻塞打开，等待 AFLNet 连接
	fuzz_ctl_fd = open(FUZZ_CTL_PIPE, O_RDONLY | O_NONBLOCK);
	if (fuzz_ctl_fd < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "open %s failed", FUZZ_CTL_PIPE);
		return -1;
	}
	// 状态管道以 O_RDWR 打开，保证无读者时也能写入
	fuzz_st_fd = open(FUZZ_ST_PIPE, O_RDWR | O_NONBLOCK);
	if (fuzz_st_fd < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "open %s failed", FUZZ_ST_PIPE);
		close(fuzz_ctl_fd);
		fuzz_ctl_fd = -1;
		return -1;
	}

	// 自动保存快照通知管道，O_RDWR 打开避免无写端时立即 EOF
	unlink(FUZZ_AUTO_PIPE);
	if (mkfifo(FUZZ_AUTO_PIPE, 0666) < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mkfifo %s failed", FUZZ_AUTO_PIPE);
		return -1;
	}
	fuzz_auto_fd = open(FUZZ_AUTO_PIPE, O_RDWR | O_NONBLOCK);
	if (fuzz_auto_fd < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "open %s failed", FUZZ_AUTO_PIPE);
		return -1;
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "pipes created: ctl=%s st=%s", FUZZ_CTL_PIPE, FUZZ_ST_PIPE);
	return 0;
}

// 保存快照并备份覆盖率状态，成功返回 true
static bool fuzz_do_save_snapshot(void) {
	vm_stop(RUN_STATE_SAVE_VM);
	Error *err = NULL;
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "saving snapshot");
	if (!save_snapshot(FUZZ_SNAPSHOT_NAME, true, NULL, false, NULL, &err)) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "save_snapshot failed");
		return false;
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "snapshot saved: %s", FUZZ_SNAPSHOT_NAME);
	// 输出保存快照前捕获的覆盖率（尚未开始 fuzz 轮次）
	fuzz_coverage_dump(0);
	fuzz_coverage_backup();
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "coverage state backed up");
	return true;
}

// 自动保存快照通知管道回调（coverage 识别到目标入口后写入）
static void fuzz_auto_handler(void *opaque) {
	if (fuzz_auto_fd < 0) {
		return;
	}
	unsigned char dummy;
	ssize_t n = read(fuzz_auto_fd, &dummy, 1);
	if (n == 0) {
		// 对端关闭，注销 handler 避免持续空转
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "auto snapshot pipe disconnected");
		qemu_set_fd_handler(fuzz_auto_fd, NULL, NULL, NULL);
		close(fuzz_auto_fd);
		fuzz_auto_fd = -1;
		return;
	}
	if (n < 0) {
		if (errno == EAGAIN) {
			// 无数据，等待下次回调
			return;
		}
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "read auto pipe failed: %s", strerror(errno));
		return;
	}

	fuzz_do_save_snapshot();
}

// 向状态管道写入 status，失败仅记录日志
static void fuzz_write_status(uint32_t status) {
	if (write(fuzz_st_fd, &status, sizeof(status)) != (ssize_t)sizeof(status)) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "write status pipe failed");
	}
}

// 结束本轮测试：拷贝 edge bitmap 与退出状态到共享内存并通知 AFLNet
static void fuzz_finish_test(void) {
	fuzz_coverage_copy_edge_map(shm_edge_map);

	// 目标进程退出状态（waitpid 格式），供 AFLNet 判断正常退出/崩溃
	if (shm_exit_status) {
		*shm_exit_status = fuzz_coverage_get_exit_status();
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "exit status 0x%08x copied to shared memory", *shm_exit_status);
	}

	fuzz_write_status(1);
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "test #%d finished, coverage copied to shared memory", fuzz_forkserver_count);
	fuzz_coverage_dump(fuzz_forkserver_count);
}

// 快照恢复等待结束，通知 fuzzer 新一轮测试可以开始
static void fuzz_restore_timer_cb(void *opaque) {
	fuzz_write_status(1);
}

// 程序处理等待结束，拷贝覆盖率并通知 fuzzer
static void fuzz_copy_timer_cb(void *opaque) {
	fuzz_finish_test();
}

// 懒创建延迟定时器：fuzz_set_enabled 在选项解析期执行，早于 qemu_init_timers，此时建 timer 会挂空定时器列表
static void fuzz_timer_ensure(void) {
	if (!fuzz_restore_timer) {
		fuzz_restore_timer = timer_new_ns(QEMU_CLOCK_REALTIME, fuzz_restore_timer_cb, NULL);
	}
	if (!fuzz_copy_timer) {
		fuzz_copy_timer = timer_new_ns(QEMU_CLOCK_REALTIME, fuzz_copy_timer_cb, NULL);
	}
}

// AFLNet 控制管道回调
static void fuzz_ctl_handler(void *opaque) {
	unsigned char cmd;
	ssize_t n = read(fuzz_ctl_fd, &cmd, 1);
	if (n == 0) {
		// AFLNet 断开，FIFO 无写端后保持可读，必须注销 handler 否则会持续空转
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "AFLNet disconnected");
		qemu_set_fd_handler(fuzz_ctl_fd, NULL, NULL, NULL);
		close(fuzz_ctl_fd);
		fuzz_ctl_fd = -1;
		return;
	}
	if (n < 0) {
		if (errno == EAGAIN) {
			// 无数据，等待下次回调
			return;
		}
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "read ctl pipe failed: %s", strerror(errno));
		return;
	}

	if (cmd == 0x01) {
		// 自动保存快照模式下忽略手动 0x01 命令，不回写备份
		if (fuzz_coverage_auto_snapshot()) {
			fuzz_write_status(1);
			g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "auto save mode enabled, manual save command ignored");
			return;
		}
		// 保存快照，由用户控制时机，目标程序已处于稳定状态
		fuzz_write_status(fuzz_do_save_snapshot() ? 1 : 2);
		return;
	}

	if (cmd == 0x02) {
		// 恢复到保存快照时的覆盖率状态，再恢复 VM
		fuzz_coverage_reset();

		fuzz_forkserver_count++;
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "received fuzz command #%d", fuzz_forkserver_count);

		Error *err = NULL;
		if (!load_snapshot(FUZZ_SNAPSHOT_NAME, NULL, false, NULL, &err)) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "load_snapshot failed");
			fuzz_write_status(2);
			return;
		}
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "snapshot restored");

		vm_start();
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "vm started");

		// 不能在本 handler 内 sleep 等待恢复：vm_start 要等本函数返回后才真正开始恢复虚拟机
		// 用主循环定时器延迟发送 status，期间 vCPU 线程已恢复执行
		int64_t wait_ms = fuzz_coverage_wait_snapshot_restore_ms();
		if (wait_ms > 0) {
			fuzz_timer_ensure();
			timer_mod(fuzz_restore_timer, qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + wait_ms * (int64_t)SCALE_MS);
		} else {
			fuzz_write_status(1);
		}
		return;
	}

	if (cmd == 0x03) {
		// 先等待程序处理完本轮输入，再拷贝 edge bitmap 到共享内存并通知 AFLNet
		int64_t wait_ms = fuzz_coverage_wait_program_done_ms();
		if (wait_ms > 0) {
			fuzz_timer_ensure();
			timer_mod(fuzz_copy_timer, qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + wait_ms * (int64_t)SCALE_MS);
		} else {
			fuzz_finish_test();
		}
		return;
	}

	g_log(LOG_DOMAIN, G_LOG_LEVEL_WARNING, "unknown fuzz command: 0x%02x", cmd);
}

// 设置 forkserver 启用状态
void fuzz_set_enabled(bool enabled) {
	if (enabled) {
		fuzz_fs_enabled = true;
		fuzz_init_log();
		fuzz_create_shm();
		fuzz_create_exit_shm();
		if (fuzz_init_pipes() < 0) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "pipe initialization failed, forkserver disabled");
			return;
		}
		qemu_set_fd_handler(fuzz_ctl_fd, fuzz_ctl_handler, NULL, NULL);
		qemu_set_fd_handler(fuzz_auto_fd, fuzz_auto_handler, NULL, NULL);
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "enabled, waiting for AFLNet on %s", FUZZ_CTL_PIPE);
	}
}

// fuzz 模式是否已启用（由 -fuzz 参数触发）
bool fuzz_enabled(void) {
	return fuzz_fs_enabled;
}