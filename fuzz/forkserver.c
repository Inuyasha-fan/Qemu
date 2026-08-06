#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "sysemu/cpus.h"
#include "sysemu/runstate.h"
#include "migration/snapshot.h"
#include "fuzz/forkserver.h"

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
static int fuzz_notify_fd = -1;
static int fuzz_forkserver_count = 0;
static bool fuzz_debug = false;

// 三段共享内存指针
static uint8_t *shm_edge_map = NULL;
static FuzzShmCov *shm_cov = NULL;
static FuzzShmTrace *shm_trace = NULL;

// 深拷贝缓冲区
static uint8_t *edge_backup = NULL;
static FuzzShmCov *cov_backup = NULL;
static FuzzShmTrace *trace_backup = NULL;

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
		g_log_set_handler(
			LOG_DOMAIN,
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
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mkfifo %s failed", FUZZ_CTL_PIPE);
		return;
	}
	unlink(FUZZ_ST_PIPE);
	if (mkfifo(FUZZ_ST_PIPE, 0666) < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mkfifo %s failed", FUZZ_ST_PIPE);
		return;
	}
	unlink(FUZZ_NOTIFY_PIPE);
	if (mkfifo(FUZZ_NOTIFY_PIPE, 0666) < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mkfifo %s failed", FUZZ_NOTIFY_PIPE);
		return;
	}

	fuzz_notify_fd = open(FUZZ_NOTIFY_PIPE, O_RDONLY | O_NONBLOCK);
	if (fuzz_notify_fd < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "open %s failed", FUZZ_NOTIFY_PIPE);
		return;
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "notify pipe created at %s", FUZZ_NOTIFY_PIPE);
}

// 附着到插件已创建的共享内存
static void fuzz_attach_shm(void) {
	int shmid;

	shmid = shmget(FUZZ_SHM_EDGE_KEY, FUZZ_SHM_EDGE_SIZE, 0666);
	if (shmid >= 0) {
		shm_edge_map = (uint8_t *)shmat(shmid, NULL, 0);
		if (shm_edge_map == (void *)-1) shm_edge_map = NULL;
	}

	shmid = shmget(FUZZ_SHM_COV_KEY, FUZZ_SHM_COV_SIZE, 0666);
	if (shmid >= 0) {
		shm_cov = (FuzzShmCov *)shmat(shmid, NULL, 0);
		if (shm_cov == (void *)-1) shm_cov = NULL;
	}

	shmid = shmget(FUZZ_SHM_TRACE_KEY, FUZZ_SHM_TRACE_SIZE, 0666);
	if (shmid >= 0) {
		shm_trace = (FuzzShmTrace *)shmat(shmid, NULL, 0);
		if (shm_trace == (void *)-1) shm_trace = NULL;
	}

	if (shm_edge_map && shm_cov && shm_trace) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "attached to shared memory");
	} else {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "failed to attach to shared memory");
	}
}

// 深拷贝共享内存
static void shm_deep_copy(void) {
	if (shm_edge_map) {
		if (!edge_backup) edge_backup = g_malloc(FUZZ_SHM_EDGE_SIZE);
		memcpy(edge_backup, shm_edge_map, FUZZ_SHM_EDGE_SIZE);
	}
	if (shm_cov) {
		if (!cov_backup) cov_backup = g_malloc(FUZZ_SHM_COV_SIZE);
		memcpy(cov_backup, shm_cov, FUZZ_SHM_COV_SIZE);
	}
	if (shm_trace) {
		if (!trace_backup) trace_backup = g_malloc(FUZZ_SHM_TRACE_SIZE);
		memcpy(trace_backup, shm_trace, FUZZ_SHM_TRACE_SIZE);
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "shared memory deep copied");
}

// 恢复共享内存
static void shm_restore(void) {
	if (shm_edge_map && edge_backup)
		memcpy(shm_edge_map, edge_backup, FUZZ_SHM_EDGE_SIZE);
	if (shm_cov && cov_backup)
		memcpy(shm_cov, cov_backup, FUZZ_SHM_COV_SIZE);
	if (shm_trace && trace_backup)
		memcpy(shm_trace, trace_backup, FUZZ_SHM_TRACE_SIZE);
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "shared memory restored");
}

// 输出覆盖率信息
static void dump_fuzz_coverage_info(void) {
	uint32_t tb_count = 0;
	if (shm_cov) {
		if (fuzz_debug) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
				"%s,%s,%s,%s,%s",
				"virt_addr", "phys_addr",
				"trans_count", "exec_count", "insn_count");
		}
		for (uint32_t i = 0; i < FUZZ_MAX_TB_ENTRIES; i++) {
			ShmCoverageEntry *e = &shm_cov->entries[i];
			if (e->virt_addr == 0) continue;
			tb_count++;
			if (fuzz_debug) {
				g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
					"0x%016" PRIx64 ",0x%016" PRIx64 ","
					"%" PRIu64 ",%" PRIu64 ",%" PRIu64,
					e->virt_addr, e->phys_addr,
					e->trans_count, e->exec_count, e->insn_count);
			}
		}
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "%u TB entries", tb_count);

	uint32_t edge_count = 0;
	if (shm_edge_map) {
		for (uint32_t i = 0; i < EDGE_MAP_SIZE; i++) {
			if (shm_edge_map[i] != 0) edge_count++;
		}
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "edge coverage: %" PRIu32 " edges hit", edge_count);

	uint32_t trace_total = 0;
	if (shm_trace) {
		if (fuzz_debug) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
				"%s,%s,%s",
				"virt_addr", "cur_loc", "exec_count");
		}
		for (uint32_t i = 0; i < shm_trace->trace_idx; i++) {
			ShmTraceEntry *t = &shm_trace->entries[i];
			trace_total += t->exec_count;
			if (fuzz_debug) {
				g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
					"0x%016" PRIx64 ",0x%08" PRIx32 ",%" PRIu32,
					t->virt_addr, t->cur_loc, t->exec_count);
			}
		}
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "execution trace: %" PRIu32 " entries, trace_idx: %" PRIu32, trace_total, shm_trace->trace_idx);
}

// AFLNet 控制管道回调
static void fuzz_ctl_handler(void *opaque) {
	dump_fuzz_coverage_info();
	shm_restore();

	unsigned char cmd;
	ssize_t n = read(fuzz_ctl_fd, &cmd, 1);
	if (n <= 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "AFLNet disconnected, cleaning up");
		qemu_set_fd_handler(fuzz_ctl_fd, NULL, NULL, NULL);
		close(fuzz_ctl_fd);
		fuzz_ctl_fd = -1;
		close(fuzz_st_fd);
		fuzz_st_fd = -1;
		return;
	}

	if (cmd == 0x01) {
		fuzz_forkserver_count++;
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "received fuzz command #%d", fuzz_forkserver_count);

		Error *err = NULL;
		if (!load_snapshot(FUZZ_SNAPSHOT_NAME, NULL, false, NULL, &err)) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "load_snapshot failed");
			uint32_t status = 1;
			write(fuzz_st_fd, &status, 4);
			return;
		}
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "snapshot restored");

		vm_start();
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "vm started");

		uint32_t status = 0;
		write(fuzz_st_fd, &status, 4);
	}
}

// 插件通知回调
static void fuzz_pipe_handler(void *opaque) {
	char buf[4];
	if (read(fuzz_notify_fd, buf, 4) != 4) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "read notify pipe failed");
		return;
	}
	// 验证读取的内容必须是 FORK
	if (buf[0] != 'F' || buf[1] != 'O' || buf[2] != 'R' || buf[3] != 'K') {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "invalid notification: expected FORK");
		return;
	}

	Error *err = NULL;

	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "saving snapshot");
	if (!save_snapshot(FUZZ_SNAPSHOT_NAME, true, NULL, false, NULL, &err)) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "save_snapshot failed");
		return;
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "snapshot saved: %s", FUZZ_SNAPSHOT_NAME);

	shm_deep_copy();

	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "waiting for AFLNet on %s", FUZZ_CTL_PIPE);
	fuzz_ctl_fd = open(FUZZ_CTL_PIPE, O_RDONLY);
	if (fuzz_ctl_fd < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "open %s failed", FUZZ_CTL_PIPE);
		return;
	}
	fuzz_st_fd = open(FUZZ_ST_PIPE, O_WRONLY);
	if (fuzz_st_fd < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "open %s failed", FUZZ_ST_PIPE);
		close(fuzz_ctl_fd);
		fuzz_ctl_fd = -1;
		return;
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "AFLNet connected");

	qemu_set_fd_handler(fuzz_ctl_fd, fuzz_ctl_handler, NULL, NULL);
}

// 设置 forkserver 启用状态
void fuzz_set_enabled(bool enabled) {
	if (enabled) {
		fuzz_init_log();
		fuzz_attach_shm();
		fuzz_init_pipes();
		qemu_set_fd_handler(fuzz_notify_fd, fuzz_pipe_handler, NULL, NULL);
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "enabled, notify pipe at %s", FUZZ_NOTIFY_PIPE);
	}
}

// 设置 debug 日志等级
void fuzz_set_debug(bool enabled) {
	fuzz_debug = enabled;
	if (enabled) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "debug logging enabled");
	}
}
