#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <glib.h>
#include <qemu-plugin.h>

#include "common.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static bool do_inline;
static int mode = -1;
static GMutex lock;
static FILE *log_fp;
static const char *log_path = "Logs/coverage.log";
static ElfEntryInfo entry_info;
static bool is_system;
static uint64_t target_asid;
static bool target_found;

// 三段共享内存指针
static uint8_t *shm_edge_map = NULL;
static FuzzShmCov *shm_cov = NULL;
static FuzzShmTrace *shm_trace = NULL;

// fuzz 模式相关
static bool fuzz_mode;
static bool fuzz_notified;
static int fuzz_notify_fd = -1;

static void dump_coverage_info(void) {
	g_mutex_lock(&lock);

	uint32_t tb_count = 0;
	if (entry_info.debug) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
			"%s,%s,%s,%s,%s",
			"virt_addr",
			"phys_addr",
			"trans_count",
			"exec_count",
			"insn_count"
		);
	}
	for (uint32_t i = 0; i < FUZZ_MAX_TB_ENTRIES; i++) {
		ShmCoverageEntry *e = &shm_cov->entries[i];
		if (e->virt_addr == 0) {
			continue;
		}
		tb_count++;
		if (entry_info.debug) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
				"0x%016"PRIx64",0x%016"PRIx64","
				"%"PRIu64",%"PRIu64",%"PRIu64"",
				e->virt_addr,
				e->phys_addr,
				e->trans_count,
				e->exec_count,
				e->insn_count
			);
		}
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "%u TB entries collected", tb_count);

	uint32_t edge_count = shm_edge_count(shm_edge_map);

	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "edge coverage: %" PRIu32 " edges hit", edge_count);

	uint32_t trace_total = 0;
	if (entry_info.debug) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
			"%s,%s,%s",
			"virt_addr",
			"cur_loc",
			"exec_count"
		);
	}
	for (uint32_t i = 0; i < shm_trace->trace_idx; i++) {
		ShmTraceEntry *t = &shm_trace->entries[i];
		trace_total += t->exec_count;
		if (entry_info.debug) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
				"0x%016" PRIx64 ",0x%08" PRIx32 ",%" PRIu32,
				t->virt_addr,
				t->cur_loc,
				t->exec_count
			);
		}
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "execution trace: %" PRIu32 " entries, trace_idx: %" PRIu32, trace_total, shm_trace->trace_idx);

	g_mutex_unlock(&lock);
}

static void plugin_exit(qemu_plugin_id_t id, void *p) {
	dump_coverage_info();

	if (fuzz_notify_fd >= 0) {
		close(fuzz_notify_fd);
		fuzz_notify_fd = -1;
	}

	fclose(log_fp);
	log_fp = NULL;
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata) {
	uint64_t virt_addr = (uint64_t)(uintptr_t)udata;

	// fuzz 模式：检测入口函数执行，通知 forkserver（仅通知一次）
	if (virt_addr == entry_info.addr && fuzz_mode && !fuzz_notified) {
		fuzz_notified = true;
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "fuzz mode: _start hit, notifying forkserver");

		fuzz_notify_fd = open(FUZZ_NOTIFY_PIPE, O_WRONLY);
		if (fuzz_notify_fd < 0) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "open %s failed", FUZZ_NOTIFY_PIPE);
			return;
		}
		char buf[4] = "FORK";
		if (write(fuzz_notify_fd, buf, 4) == 4) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "fuzz mode: notification sent to forkserver");
		} else {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "write %s failed", FUZZ_NOTIFY_PIPE);
			return;
		}
	}

	g_mutex_lock(&lock);
	ShmCoverageEntry *cnt = shm_coverage_lookup(shm_cov, virt_addr);
	g_assert(cnt);
	cnt->exec_count++;

	uint64_t cur_loc = (virt_addr >> 4) ^ (virt_addr << 8);
	cur_loc &= EDGE_MAP_SIZE - 1;

	if (cur_loc < entry_info.inst_ratio) {
		uint32_t edge_idx = cur_loc ^ shm_trace->prev_loc_exec;
		shm_edge_map[edge_idx]++;
		shm_trace->prev_loc_exec = cur_loc >> 1;

		if (shm_trace->trace_idx > 0 &&
			shm_trace->entries[shm_trace->trace_idx - 1].cur_loc == (uint32_t)cur_loc) {
			shm_trace->entries[shm_trace->trace_idx - 1].exec_count++;
		} else if (shm_trace->trace_idx < FUZZ_MAX_TRACE_ENTRIES) {
			ShmTraceEntry *t = &shm_trace->entries[shm_trace->trace_idx];
			t->virt_addr = virt_addr;
			t->cur_loc = (uint32_t)cur_loc;
			t->exec_count = 1;
			shm_trace->trace_idx++;
		}
	}
	g_mutex_unlock(&lock);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
	uint64_t virt_addr = qemu_plugin_tb_vaddr(tb);
	uint64_t asid = qemu_plugin_tb_get_asid(tb);
	uint64_t phys_addr = qemu_plugin_tb_get_phys_addr(tb);

	if (mode == 0) {
		// 全收集，无过滤
	} else if (target_found) {
		if (asid != target_asid) {
			return;
		}
		if (virt_addr < entry_info.text_start || virt_addr > entry_info.text_start + entry_info.text_size) {
			return;
		}
	} else if (asid == 0 && is_system) {
		return;
	} else if (mode == 1 || mode == 4) {
		if (virt_addr != entry_info.addr) {
			return;
		}
		uint64_t id_asid = try_identify_target(&entry_info, asid, phys_addr);
		if (id_asid == (uint64_t)-1) {
			return;
		}
		target_asid = id_asid;
		target_found = true;
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "target process identified: ASID=0x%02" PRIx64, target_asid);
	} else if (mode == 2 || mode == 3) {
		uint64_t id_asid = try_identify_target(&entry_info, asid, phys_addr);
		if (id_asid == (uint64_t)-1) {
			return;
		}
		if (!target_found) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "target entry point found at 0x%016" PRIx64, virt_addr);
		}
		target_asid = id_asid;
		target_found = true;
		if (mode == 2) {
			uint64_t offset = virt_addr - entry_info.addr;
			entry_info.text_start += offset;
		}
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "target process identified: ASID=0x%02" PRIx64, target_asid);
	} else {
		return;
	}

	size_t insn_count = qemu_plugin_tb_n_insns(tb);

	g_mutex_lock(&lock);
	ShmCoverageEntry *cnt = shm_coverage_insert(shm_cov, virt_addr);
	if (cnt) {
		if (cnt->trans_count == 0) {
			cnt->phys_addr = phys_addr;
			cnt->insn_count = insn_count;
		}
		cnt->trans_count++;
	}
	g_mutex_unlock(&lock);

	if (do_inline) {
		qemu_plugin_register_vcpu_tb_exec_inline(
			tb,
			QEMU_PLUGIN_INLINE_ADD_U64,
			&cnt->exec_count,
			1
		);
	} else {
		qemu_plugin_register_vcpu_tb_exec_cb(
			tb,
			vcpu_tb_exec,
			QEMU_PLUGIN_CB_NO_REGS,
			(gpointer)(uintptr_t)virt_addr
		);
	}
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv) {
	is_system = info->system_emulation;
	fuzz_mode = info->fuzz_mode;

	char *config_path = NULL;
	for (int i = 0; i < argc; i++) {
		char *opt = argv[i];
		g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
		if (g_strcmp0(tokens[0], "inline") == 0) {
			if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &do_inline)) {
				g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "boolean argument parsing failed: %s", opt);
				return -1;
			}
		} else if (g_strcmp0(tokens[0], "config") == 0) {
			config_path = g_strdup(tokens[1]);
		} else {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "option parsing failed: %s", opt);
			return -1;
		}
	}

	if (!config_path) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "config=<path> is required");
		return -1;
	}

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

	// 初始化三段共享内存
	if (fuzz_init_shm(&shm_edge_map, &shm_cov, &shm_trace) < 0) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "failed to initialize shared memory");
		return -1;
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO,
		"shared memory initialized: edge=%lu cov=%lu trace=%lu",
		(unsigned long)FUZZ_SHM_EDGE_SIZE, (unsigned long)FUZZ_SHM_COV_SIZE, (unsigned long)FUZZ_SHM_TRACE_SIZE);

	char *elf_path = NULL;
	ParseResult ret = parse_config(config_path, &entry_info, &elf_path, &mode);
	if (ret != PARSE_OK) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "failed to parse config: %s", config_path);
		return -1;
	}

	if (entry_info.inst_ratio > EDGE_MAP_SIZE) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "inst_ratio %" PRIu32 " exceeds EDGE_MAP_SIZE", entry_info.inst_ratio);
		return -1;
	}

	if (mode == 0) {
		if (is_system) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mode 0 is only valid in user emulation mode");
			return -1;
		}
	} else {
		if ((mode == 1 || mode == 2) && (!elf_path || elf_path[0] == '\0')) {
			g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mode %d requires elf_path in config", mode);
			return -1;
		}

		if (mode == 1 || mode == 2) {
			ParseResult elf_ret = parse_elf(elf_path, &entry_info);
			if (elf_ret != PARSE_OK) {
				g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "failed to parse ELF: %s", elf_path);
				return -1;
			}
		}

		if (mode == 3) {
			entry_info.text_start = 0;
			entry_info.text_size = UINT64_MAX;
			entry_info.addr = 0;
		}

		if (mode == 4) {
			if (entry_info.instr_count != ENTRY_INSTR_COUNT) {
				g_log(LOG_DOMAIN, G_LOG_LEVEL_ERROR, "mode 4 requires entry_code with %d instructions", ENTRY_INSTR_COUNT);
				return -1;
			}
		}
	}

	if (elf_path) {
		g_free(elf_path);
	}

	if (fuzz_mode) {
		g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "fuzz mode enabled, waiting for _start execution to trigger forkserver");
	}

	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "inst_ratio: %" PRIu32, entry_info.inst_ratio);
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "%s emulation mode, config mode: %d",
	       is_system ? "system" : "user", mode);
	g_autoptr(GString) hex = g_string_new(NULL);
	for (size_t i = 0; i < entry_info.instr_count; i++) {
		g_string_append_printf(hex, "0x%08" PRIx32 " ", entry_info.instrs[i]);
	}
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "entry instructions: %s", hex->str);
	g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO,
		"entry addr: 0x%016" PRIx64 "  text_start: 0x%016" PRIx64 "  text_size: 0x%016" PRIx64,
		entry_info.addr,
		entry_info.text_start,
		entry_info.text_size
	);

	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
	return 0;
}
