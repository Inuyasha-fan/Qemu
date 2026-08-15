// AFLNet 快照型 forkserver
//
// 与 AFLNet 通过命名管道通信，通过控制管道接收命令：
//   - 0x01：保存快照（由用户手动触发，目标程序已处于稳定状态）
//   - 0x02：执行一轮测试（加载快照、重置覆盖率、恢复虚拟机运行，
//            ack 在配置的 wait_snapshot_restore 毫秒后返回）
//   - 0x03：fuzzer 发包完成后的确认（等待配置的 wait_program_done 毫秒后
//            输出本轮终态并 ack）
// 共享内存实时更新（边 bitmap 与退出状态），0x03 仅为收尾确认与状态输出



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
// ack 定时器：vm_start() 只置运行态，VM 实际执行在主循环回调中发生，
// handler 内不能阻塞（会挡住主循环、快照恢复永不推进），
// 等待必须由定时器回调完成：handler 注册定时器后立即返回让出主循环
static QEMUTimer *fuzz_ack_timer = NULL;
static unsigned char fuzz_pending_cmd = 0;
static bool fuzz_fs_enabled = false;


// 共享内存（边覆盖 bitmap 供 AFLNet 读取，退出状态供 AFLNet 读取）
static uint8_t *shm_edge_map = NULL;
static uint32_t *shm_exit_status = NULL;
static int fuzz_edge_shmid = -1;
static int fuzz_exit_shmid = -1;

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
	fuzz_edge_shmid = shmget(FUZZ_SHM_EDGE_KEY, FUZZ_SHM_EDGE_SIZE, IPC_CREAT | 0666);
	if (fuzz_edge_shmid < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "shmget failed for key 0x%x", FUZZ_SHM_EDGE_KEY);
		return;
	}
	shm_edge_map = (uint8_t *)shmat(fuzz_edge_shmid, NULL, 0);
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
	fuzz_exit_shmid = shmget(FUZZ_SHM_EXIT_KEY, FUZZ_SHM_EXIT_SIZE, IPC_CREAT | 0666);
	if (fuzz_exit_shmid < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "shmget failed for key 0x%x", FUZZ_SHM_EXIT_KEY);
		return;
	}
	shm_exit_status = (uint32_t *)shmat(fuzz_exit_shmid, NULL, 0);
	if (shm_exit_status == (void *)-1) {
		shm_exit_status = NULL;
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "shmat failed for key 0x%x", FUZZ_SHM_EXIT_KEY);
		return;
	}
	*shm_exit_status = FUZZ_EXIT_TIMEOUT;
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "exit status shared memory created at key 0x%x", FUZZ_SHM_EXIT_KEY);

	// 共享内存即内部 edge bitmap / 退出状态的实时载体
	fuzz_coverage_set_shm(shm_edge_map, shm_exit_status);
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

	// 控制管道以 O_RDWR 打开：自身持有写端，避免无写端时立即 EOF，断开后新 fuzzer 也能重连
	fuzz_ctl_fd = open(FUZZ_CTL_PIPE, O_RDWR | O_NONBLOCK);
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

// ack 定时器回调：等待期主循环正常运行（VM 持续执行），到点后完成 ack 前动作
static void fuzz_ack_timer_cb(void *opaque) {
	(void)opaque;
	if (fuzz_pending_cmd == 0x03) {
		// 0x03：程序处理窗口结束，输出本轮终态（边覆盖 + 退出状态）后 ack
		fuzz_coverage_dump(fuzz_forkserver_count);
	}
	fuzz_pending_cmd = 0;
	fuzz_write_status(1);
}

// 0x03 命令的收尾等待与状态输出见 fuzz_ctl_handler

// AFLNet 控制管道回调
static void fuzz_ctl_handler(void *opaque) {
	unsigned char cmd;
	ssize_t n = read(fuzz_ctl_fd, &cmd, 1);
	if (n == 0) {
		// 理论不可达：ctl 以 O_RDWR 打开，自身持有写端，FIFO 不会 EOF。
		// 保留为防御：若将来改回 O_RDONLY，仍须注销 handler 避免空转。
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "fuzzer disconnected");
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
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "received fuzz command %d", fuzz_forkserver_count);

		Error *err = NULL;
		if (!load_snapshot(FUZZ_SNAPSHOT_NAME, NULL, false, NULL, &err)) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "load_snapshot failed");
			fuzz_write_status(2);
			return;
		}
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "snapshot restored");

		vm_start();
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "vm started");

		// 注册恢复等待定时器后立即返回让出主循环（VM 才能真正执行）。
		// 等待配置的快照恢复时间后由定时器回调 ack：等待期 guest 正在恢复，
		// 恢复完成后目标程序即监听并处理本轮输入。
		// 懒创建：时钟定时器列表需在主循环初始化完成后才可用
		if (!fuzz_ack_timer) {
			fuzz_ack_timer = timer_new_ns(QEMU_CLOCK_HOST, fuzz_ack_timer_cb, NULL);
		}
		fuzz_pending_cmd = cmd;
		timer_mod(fuzz_ack_timer,
		          qemu_clock_get_ns(QEMU_CLOCK_HOST) +
		          (int64_t)fuzz_coverage_wait_snapshot_restore() * 1000000);
		return;
	}

	if (cmd == 0x03) {
		// fuzzer 发包完成后的确认：注册程序处理等待定时器后让出主循环
		// （程序继续执行并实时写共享内存），到点后输出本轮终态并 ack
		if (!fuzz_ack_timer) {
			fuzz_ack_timer = timer_new_ns(QEMU_CLOCK_HOST, fuzz_ack_timer_cb, NULL);
		}
		fuzz_pending_cmd = cmd;
		timer_mod(fuzz_ack_timer,
		          qemu_clock_get_ns(QEMU_CLOCK_HOST) +
		          (int64_t)fuzz_coverage_wait_program_done() * 1000000);
		return;
	}

	g_log(LOG_DOMAIN, G_LOG_LEVEL_WARNING, "unknown fuzz command: 0x%02x", cmd);
}

// QEMU 退出时清理：删除命名管道和共享内存，避免 /tmp 与 IPC 空间残留
// （SIGKILL 等强杀无法执行本函数，残留由下次启动时的 unlink/shmget 兜底）
static void fuzz_cleanup(void) {
	if (fuzz_ctl_fd >= 0) {
		close(fuzz_ctl_fd);
		fuzz_ctl_fd = -1;
	}
	if (fuzz_st_fd >= 0) {
		close(fuzz_st_fd);
		fuzz_st_fd = -1;
	}
	if (fuzz_auto_fd >= 0) {
		close(fuzz_auto_fd);
		fuzz_auto_fd = -1;
	}
	if (fuzz_ack_timer) {
		timer_free(fuzz_ack_timer);
		fuzz_ack_timer = NULL;
	}
	unlink(FUZZ_CTL_PIPE);
	unlink(FUZZ_ST_PIPE);
	unlink(FUZZ_AUTO_PIPE);
	if (fuzz_edge_shmid >= 0) {
		shmctl(fuzz_edge_shmid, IPC_RMID, NULL);
		fuzz_edge_shmid = -1;
	}
	if (fuzz_exit_shmid >= 0) {
		shmctl(fuzz_exit_shmid, IPC_RMID, NULL);
		fuzz_exit_shmid = -1;
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "cleanup done: pipes and shared memory removed");
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
		atexit(fuzz_cleanup);
		qemu_set_fd_handler(fuzz_ctl_fd, fuzz_ctl_handler, NULL, NULL);
		qemu_set_fd_handler(fuzz_auto_fd, fuzz_auto_handler, NULL, NULL);
		// ack 定时器懒创建（首个 0x02/0x03 命令时）：定时器列表须在主循环初始化完成后才可用
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "enabled, waiting for fuzzer on %s", FUZZ_CTL_PIPE);
	}
}

// fuzz 模式是否已启用（由 -fuzz 参数触发）
bool fuzz_enabled(void) {
	return fuzz_fs_enabled;
}