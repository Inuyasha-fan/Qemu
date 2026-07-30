#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <qemu-plugin.h>

#include "common.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static bool do_inline;
static int mode = -1;
static GMutex lock;
static GHashTable *coverage_map;
static uint8_t edge_map[EDGE_MAP_SIZE];
static uint32_t edge_count;
static FILE *log_fp;
static const char *log_path = "Logs/coverage.log";
static ElfEntryInfo entry_info;
static bool is_system;
static uint64_t target_asid;
static bool target_found;

static uint32_t prev_loc_exec;
static uint32_t trace_count;
static EdgeTrace *trace_head;
static EdgeTrace *trace_tail;

static void plugin_exit(qemu_plugin_id_t id, void *p) {
	if (!log_fp) {
		return;
	}

	GHashTableIter iter;
	gpointer key, value;
	GList *list = NULL;

	g_mutex_lock(&lock);
	guint count = g_hash_table_size(coverage_map);
	g_mutex_unlock(&lock);

	g_info("%u TB entries collected", count);

	g_mutex_lock(&lock);
	g_hash_table_iter_init(&iter, coverage_map);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		SortedEntry *e = g_new(SortedEntry, 1);
		e->virt_addr = (uint64_t)(uintptr_t)key;
		e->rec = (Coverage *)value;
		list = g_list_prepend(list, e);
	}
	list = g_list_sort(list, cmp_virt_addr);

	g_info(
		"%s,%s,%s,%s,%s",
		"virt_addr",
		"phys_addr",
		"trans_count",
		"exec_count",
		"insn_count"
	);

	for (GList *l = list; l; l = l->next) {
		SortedEntry *e = l->data;
		Coverage *rec = e->rec;
		if (entry_info.debug) {
			g_debug(
				"0x%016"PRIx64",0x%016"PRIx64","
				"%"PRIu64",%"PRIu64",%"PRIu64"",
				e->virt_addr,
				rec->phys_addr,
				rec->trans_count,
				rec->exec_count,
				rec->insn_count
			);
		}
	}

	g_list_free_full(list, g_free);
	g_mutex_unlock(&lock);

	g_info("edge coverage: %" PRIu32 " edges hit", edge_count);
	g_info("execution trace: %" PRIu32 " entries", trace_count);
	g_info(
		"%s,%s,%s",
		"virt_addr",
		"cur_loc",
		"exec_count"
	);
	for (EdgeTrace *t = trace_head; t; t = t->next) {
		if (entry_info.debug) {
			g_debug(
				"0x%016" PRIx64 ",0x%08" PRIx32 ",%" PRIu32,
				t->virt_addr,
				t->cur_loc,
				t->exec_count
			);
		}
	}

	while (trace_head) {
		EdgeTrace *t = trace_head;
		trace_head = t->next;
		g_free(t);
	}

	fclose(log_fp);
	log_fp = NULL;
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata) {
	uint64_t virt_addr = (uint64_t)(uintptr_t)udata;

	g_mutex_lock(&lock);
	Coverage *cnt = (Coverage *)g_hash_table_lookup(coverage_map, (gconstpointer)(uintptr_t)virt_addr);
	g_assert(cnt);
	cnt->exec_count++;

	uint64_t cur_loc = (virt_addr >> 4) ^ (virt_addr << 8);
	cur_loc &= EDGE_MAP_SIZE - 1;

	// 边覆盖和轨迹只在采样范围内记录
	if (cur_loc < entry_info.inst_ratio) {
		uint32_t edge_idx = cur_loc ^ prev_loc_exec;
		if (edge_map[edge_idx] == 0) {
			edge_count++;
		}
		edge_map[edge_idx]++;
		prev_loc_exec = cur_loc >> 1;
		trace_count++;
		// 相邻同 cur_loc 不新增节点，只累加 exec_count
		if (trace_tail && trace_tail->cur_loc == (uint32_t)cur_loc) {
			trace_tail->exec_count++;
		} else {
			EdgeTrace *t = g_new0(EdgeTrace, 1);
			t->virt_addr = virt_addr;
			t->cur_loc = (uint32_t)cur_loc;
			t->exec_count = 1;
			if (!trace_head) {
				trace_head = t;
				trace_tail = t;
			} else {
				trace_tail->next = t;
				trace_tail = t;
			}
		}
	}
	g_mutex_unlock(&lock);
}

// mode 0: user 模式收集全部，不做任何过滤
// mode 1: 已知入口地址 + ELF 解析，在入口处比对机器码
// mode 2: ASLR + ELF 解析，自动定位入口
// mode 3: ASLR 全范围，不解析 ELF
// mode 4: 手动填入字段，在入口处比对机器码
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
		g_info("target process identified: ASID=0x%02" PRIx64, target_asid);
	} else if (mode == 2 || mode == 3) {
		uint64_t id_asid = try_identify_target(&entry_info, asid, phys_addr);
		if (id_asid == (uint64_t)-1) {
			return;
		}
		if (!target_found) {
			g_info("target entry point found at 0x%016" PRIx64, virt_addr);
		}
		target_asid = id_asid;
		target_found = true;
		if (mode == 2) {
			uint64_t offset = virt_addr - entry_info.addr;
			entry_info.text_start += offset;
		}
		g_info("target process identified: ASID=0x%02" PRIx64, target_asid);
	} else {
		return;
	}

	size_t insn_count = qemu_plugin_tb_n_insns(tb);
	uint64_t key = virt_addr;

	g_mutex_lock(&lock);
	Coverage *cnt = (Coverage *)g_hash_table_lookup(coverage_map, (gconstpointer)(uintptr_t)key);
	if (cnt) {
		cnt->trans_count++;
	} else {
		cnt = g_new0(Coverage, 1);
		cnt->phys_addr = phys_addr;
		cnt->trans_count = 1;
		cnt->insn_count = insn_count;
		g_hash_table_insert(coverage_map, (gpointer)(uintptr_t)key, cnt);
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
			(gpointer)(uintptr_t)key
		);
	}
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv) {
	is_system = info->system_emulation;

	char *config_path = NULL;
	for (int i = 0; i < argc; i++) {
		char *opt = argv[i];
		g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
		if (g_strcmp0(tokens[0], "inline") == 0) {
			if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &do_inline)) {
				g_error("boolean argument parsing failed: %s", opt);
				return -1;
			}
		} else if (g_strcmp0(tokens[0], "config") == 0) {
			config_path = g_strdup(tokens[1]);
		} else {
			g_error("option parsing failed: %s", opt);
			return -1;
		}
	}

	if (!config_path) {
		g_error("config=<path> is required");
		return -1;
	}

	coverage_map = g_hash_table_new(NULL, g_direct_equal);
	memset(edge_map, 0, sizeof(edge_map));

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

	char *elf_path = NULL;
	ParseResult ret = parse_config(config_path, &entry_info, &elf_path, &mode);
	if (ret != PARSE_OK) {
		g_error("failed to parse config: %s", config_path);
		return -1;
	}

	if (entry_info.inst_ratio > EDGE_MAP_SIZE) {
		g_error("inst_ratio %" PRIu32 " exceeds EDGE_MAP_SIZE", entry_info.inst_ratio);
		return -1;
	}

	// mode 0: user 全收集，跳过配置校验
	if (mode == 0) {
		if (is_system) {
			g_error("mode 0 is only valid in user emulation mode");
			return -1;
		}
	} else {
		if ((mode == 1 || mode == 2) && (!elf_path || elf_path[0] == '\0')) {
			g_error("mode %d requires elf_path in config", mode);
			return -1;
		}

		if (mode == 1 || mode == 2) {
			ParseResult elf_ret = parse_elf(elf_path, &entry_info);
			if (elf_ret != PARSE_OK) {
				g_error("failed to parse ELF: %s", elf_path);
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
				g_error("mode 4 requires entry_code with %d instructions", ENTRY_INSTR_COUNT);
				return -1;
			}
		}
	}

	if (elf_path) {
		g_free(elf_path);
	}

	g_info("inst_ratio: %" PRIu32, entry_info.inst_ratio);

	g_info("%s emulation mode, config mode: %d",
	       is_system ? "system" : "user", mode);
	g_autoptr(GString) hex = g_string_new(NULL);
	for (size_t i = 0; i < entry_info.instr_count; i++) {
		g_string_append_printf(hex, "0x%08" PRIx32 " ", entry_info.instrs[i]);
	}
	g_info("entry instructions: %s", hex->str);
	g_info(
		"entry addr: 0x%016" PRIx64 "  text_start: 0x%016" PRIx64 "  text_size: 0x%016" PRIx64,
		entry_info.addr,
		entry_info.text_start,
		entry_info.text_size
	);

	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
	return 0;
}
