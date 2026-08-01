#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "sysemu/cpus.h"
#include "sysemu/runstate.h"
#include "migration/snapshot.h"
#include "fuzz/forkserver.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// 内部变量
static FILE *log_fp;
static const char *log_path = "Logs/forkserver.log";
static int fuzz_ctl_fd = -1;
static int fuzz_st_fd = -1;
static int fuzz_notify_fd = -1;
static int fuzz_forkserver_count = 0;

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
	log_fp = fopen(log_path, "a");
	if (log_fp) {
		g_log_set_handler(
			NULL,
			G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL,
			log_handler,
			log_fp
		);
	}
}

// 初始化 forkserver 管道
static void fuzz_init_pipes(void) {
	unlink(FUZZ_CTL_PIPE);
	if (mkfifo(FUZZ_CTL_PIPE, 0666) < 0) {
		g_error("mkfifo %s failed", FUZZ_CTL_PIPE);
		return;
	}
	unlink(FUZZ_ST_PIPE);
	if (mkfifo(FUZZ_ST_PIPE, 0666) < 0) {
		g_error("mkfifo %s failed", FUZZ_ST_PIPE);
		return;
	}
	unlink(FUZZ_NOTIFY_PIPE);
	if (mkfifo(FUZZ_NOTIFY_PIPE, 0666) < 0) {
		g_error("mkfifo %s failed", FUZZ_NOTIFY_PIPE);
		return;
	}
	fuzz_notify_fd = open(FUZZ_NOTIFY_PIPE, O_RDONLY | O_NONBLOCK);
	if (fuzz_notify_fd < 0) {
		g_error("open %s failed", FUZZ_NOTIFY_PIPE);
		return;
	}
	g_info("pipes created at %s, %s, %s", FUZZ_CTL_PIPE, FUZZ_ST_PIPE, FUZZ_NOTIFY_PIPE);
}

// 清理 forkserver 资源
static void fuzz_cleanup(void) {
	if (fuzz_ctl_fd >= 0) {
		close(fuzz_ctl_fd);
		fuzz_ctl_fd = -1;
	}
	if (fuzz_st_fd >= 0) {
		close(fuzz_st_fd);
		fuzz_st_fd = -1;
	}
	if (fuzz_notify_fd >= 0) {
		close(fuzz_notify_fd);
		fuzz_notify_fd = -1;
	}
	unlink(FUZZ_CTL_PIPE);
	unlink(FUZZ_ST_PIPE);
	unlink(FUZZ_NOTIFY_PIPE);

	if (log_fp) {
		fclose(log_fp);
		log_fp = NULL;
	}
}

// forkserver 主循环
static void fuzz_forkserver_loop(void) {
	g_info("waiting for AFLNet on %s", FUZZ_CTL_PIPE);

	fuzz_ctl_fd = open(FUZZ_CTL_PIPE, O_RDONLY);
	if (fuzz_ctl_fd < 0) {
		g_error("open %s failed", FUZZ_CTL_PIPE);
		return;
	}
	fuzz_st_fd = open(FUZZ_ST_PIPE, O_WRONLY);
	if (fuzz_st_fd < 0) {
		g_error("open %s failed", FUZZ_ST_PIPE);
		close(fuzz_ctl_fd);
		return;
	}

	g_info("AFLNet connected, entering loop");

	while (1) {
		unsigned char cmd;
		ssize_t n = read(fuzz_ctl_fd, &cmd, 1);
		if (n != 1) {
			g_error("read ctl pipe failed");
			break;
		} else if (cmd == 0x01) {
			fuzz_forkserver_count++;
			g_info("received test command #%d", fuzz_forkserver_count);

			Error *err = NULL;
			if (!load_snapshot("fuzz_snapshot", NULL, false, NULL, &err)) {
				g_error("load_snapshot failed");
				uint32_t status = 1;
				write(fuzz_st_fd, &status, 4);
				break;
			}
			g_info("snapshot restored");
			
			vm_start();

			uint32_t status = 0;
			write(fuzz_st_fd, &status, 4);
		} else {
			break;
		}
	}

	fuzz_cleanup();
}

// 管道回调函数，当插件写入通知管道时被调用
static void fuzz_pipe_handler(void *opaque) {
	char buf[4];
	if (read(fuzz_notify_fd, buf, 4) != 4) {
		g_error("read notify pipe failed");
		return;
	}
	// 验证读取的内容必须是 FORK
	if (buf[0] != 'F' || buf[1] != 'O' || buf[2] != 'R' || buf[3] != 'K') {
		g_error("invalid notification: expected FORK");
		return;
	}
	g_info("received notification, starting forkserver loop");

	
	Error *err = NULL;
	if (!save_snapshot("fuzz_snapshot", false, NULL, false, NULL, &err)) {
		g_error("save_snapshot failed");
		return;
	}
	g_info("snapshot saved");
	
	fuzz_forkserver_loop();
}

// 设置 forkserver 启用状态
void fuzz_set_enabled(bool enabled) {
	if (enabled) {
		fuzz_init_log();
		fuzz_init_pipes();
		qemu_set_fd_handler(fuzz_notify_fd, fuzz_pipe_handler, NULL, NULL);
		g_info("enabled, notify pipe at %s", FUZZ_NOTIFY_PIPE);
	}
}
