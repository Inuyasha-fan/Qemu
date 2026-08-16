/*
 * Coverage collector TCG plugin
 *
 * Collects TB / edge / trace coverage, dumped to Logs/coverage.log at exit.
 * Based on hotblocks.c and fuzz/coverage.c. Pure observation - no shared
 * memory, no target identification, no forkserver interaction.
 *
 * Usage: -plugin file=libcoverage.so,config=<path-to-config-json>
 *
 * Only "debug" and "coverage_types" fields of the config JSON are parsed.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define LOG_DOMAIN "coverage"
#define EDGE_MAP_SIZE 65536

/* Config (subset of the -fuzz config format) */
static bool cfg_debug;
static bool cfg_cov_block = true;
static bool cfg_cov_edge = true;
static bool cfg_cov_trace = true;
static uint64_t count =0;

/* TB table: key = start vaddr, value = TbEntry */
typedef struct {
    uint64_t vaddr;
    uint64_t trans_count;
    uint64_t exec_count;
    uint64_t insn_count;
} TbEntry;

static GMutex lock;
static GHashTable *tb_table;

/* Edge coverage: AFL style cur_loc xor difference */
static uint8_t edge_bitmap[EDGE_MAP_SIZE];
static uint64_t prev_loc_exec;

/* Execution trace: linked list, adjacent equal cur_loc merged */
typedef struct TraceEntry {
    uint64_t vaddr;
    uint32_t cur_loc;
    uint32_t exec_count;
    struct TraceEntry *next;
} TraceEntry;

static TraceEntry *trace_head;
static TraceEntry *trace_tail;
static uint32_t trace_count;

static FILE *log_fp;
static const char *log_path = "Logs/coverage.log";

static void log_handler(const gchar *domain, GLogLevelFlags level,
                        const gchar *message, gpointer fp)
{
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
    fprintf(log_fp, "[%s] [%s] %s\n", ts, tag, message);
    fflush(log_fp);
}

/* Parse only "debug" and "coverage_types" from the config JSON.
 * Line-based parser, kept compatible with the -fuzz config format. */
static bool parse_config(const char *path)
{
    g_autofree char *content = NULL;
    gsize len;

    if (!g_file_get_contents(path, &content, &len, NULL)) {
        return false;
    }

    g_auto(GStrv) lines = g_strsplit(content, "\n", 0);
    gboolean in_types = FALSE;
    gboolean seen_types = FALSE;

    for (int i = 0; lines[i]; i++) {
        g_autofree char *raw_line = g_strdup(lines[i]);
        char *line = g_strstrip(raw_line);

        if (line[0] == '\0' || line[0] == '/' || line[0] == '#' ||
            line[0] == '{' || line[0] == '}') {
            continue;
        }

        if (in_types) {
            if (line[0] == '"') {
                const char *val = line + 1;
                const char *end = strchr(val, '"');
                if (end) {
                    g_autofree char *v = g_strndup(val, end - val);
                    if (g_strcmp0(v, "block") == 0) {
                        cfg_cov_block = TRUE;
                    } else if (g_strcmp0(v, "edge") == 0) {
                        cfg_cov_edge = TRUE;
                    } else if (g_strcmp0(v, "trace") == 0) {
                        cfg_cov_trace = TRUE;
                    }
                }
                continue;
            }
            in_types = FALSE;
            continue;
        }

        g_auto(GStrv) kv = g_strsplit(line, ":", 2);
        if (!kv[0] || !kv[1]) {
            continue;
        }
        g_autofree char *key_raw = g_strdup(kv[0]);
        g_autofree char *val_raw = g_strdup(kv[1]);
        char *key = g_strstrip(key_raw);
        char *val = g_strstrip(val_raw);

        if (key[0] == '"') {
            key++;
        }
        size_t klen = strlen(key);
        if (klen > 1 && key[klen - 1] == '"') {
            key[klen - 1] = '\0';
        }

        size_t vlen = strlen(val);
        if (vlen > 0 && val[vlen - 1] == ',') {
            val[--vlen] = '\0';
        }
        if (vlen > 0 && val[vlen - 1] == '"') {
            val[--vlen] = '\0';
        }
        if (val[0] == '"') {
            val++;
        }

        if (g_strcmp0(key, "debug") == 0) {
            cfg_debug = (g_strcmp0(val, "true") == 0 || g_strcmp0(val, "1") == 0);
        } else if (g_strcmp0(key, "coverage_types") == 0) {
            seen_types = TRUE;
            cfg_cov_block = FALSE;
            cfg_cov_edge = FALSE;
            cfg_cov_trace = FALSE;
            in_types = TRUE;
        }
    }

    if (!seen_types) {
        cfg_cov_block = TRUE;
        cfg_cov_edge = TRUE;
        cfg_cov_trace = TRUE;
    }

    return true;
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    uint64_t vaddr = (uint64_t)(uintptr_t)udata;
    TbEntry *e;
    uint64_t cur_loc;
    uint32_t edge_idx;

    g_mutex_lock(&lock);

    e = g_hash_table_lookup(tb_table, (gconstpointer)(uintptr_t)vaddr);
    g_assert(e);
    e->exec_count++;

    cur_loc = ((vaddr >> 4) ^ (vaddr << 8)) & (EDGE_MAP_SIZE - 1);

    if (cfg_cov_edge) {
        edge_idx = (uint32_t)(cur_loc ^ prev_loc_exec);
        // if (edge_bitmap[edge_idx] == 0) {
        //     count++;
        //     g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "%d", count);
        // }
        edge_bitmap[edge_idx]++;
        prev_loc_exec = cur_loc >> 1;
    }

    if (cfg_cov_trace) {
        if (trace_count > 0 && trace_tail->cur_loc == (uint32_t)cur_loc) {
            trace_tail->exec_count++;
        } else {
            TraceEntry *t = g_new0(TraceEntry, 1);
            t->vaddr = vaddr;
            t->cur_loc = (uint32_t)cur_loc;
            t->exec_count = 1;
            if (trace_tail) {
                trace_tail->next = t;
            } else {
                trace_head = t;
            }
            trace_tail = t;
            trace_count++;
        }
    }

    g_mutex_unlock(&lock);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t vaddr = qemu_plugin_tb_vaddr(tb);
    uint64_t insns = qemu_plugin_tb_n_insns(tb);
    TbEntry *e;

    g_mutex_lock(&lock);
    e = g_hash_table_lookup(tb_table, (gconstpointer)(uintptr_t)vaddr);
    if (e) {
        e->trans_count++;
    } else {
        e = g_new0(TbEntry, 1);
        e->vaddr = vaddr;
        e->trans_count = 1;
        e->insn_count = insns;
        g_hash_table_insert(tb_table, (gpointer)(uintptr_t)vaddr, e);
    }
    g_mutex_unlock(&lock);

    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)(uintptr_t)vaddr);
}

static void dump_coverage(void)
{
    g_mutex_lock(&lock);

    if (cfg_cov_block) {
        uint32_t tb_count = g_hash_table_size(tb_table);
        if (cfg_debug) {
            g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s,%s,%s,%s",
                  "virt_addr", "trans_count", "exec_count", "insn_count");
            GHashTableIter iter;
            gpointer key, value;
            g_hash_table_iter_init(&iter, tb_table);
            while (g_hash_table_iter_next(&iter, &key, &value)) {
                TbEntry *e = value;
                g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
                      "0x%016" PRIx64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64,
                      e->vaddr, e->trans_count, e->exec_count, e->insn_count);
            }
        }
        g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO, "%u TB entries collected", tb_count);
    }

    if (cfg_cov_edge) {
        uint32_t edge_count = 0;
        for (uint32_t i = 0; i < EDGE_MAP_SIZE; i++) {
            if (edge_bitmap[i] != 0) {
                edge_count++;
            }
        }
        g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO,
              "edge coverage: %" PRIu32 " edges hit", edge_count);
    }

    if (cfg_cov_trace) {
        if (cfg_debug) {
            g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s,%s,%s",
                  "virt_addr", "cur_loc", "exec_count");
            for (TraceEntry *t = trace_head; t; t = t->next) {
                g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
                      "0x%016" PRIx64 ",0x%08" PRIx32 ",%" PRIu32,
                      t->vaddr, t->cur_loc, t->exec_count);
            }
        }
        g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO,
              "execution trace: %" PRIu32 " entries", trace_count);
    }

    g_mutex_unlock(&lock);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    dump_coverage();
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    char *config_path = NULL;

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "config") == 0) {
            config_path = g_strdup(tokens[1]);
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    if (!config_path || config_path[0] == '\0') {
        fprintf(stderr, "config=<path> is required\n");
        return -1;
    }
    g_autofree char *config_abs = realpath(config_path, NULL);
    if (!config_abs) {
        fprintf(stderr, "failed to resolve config path: %s\n", config_path);
        return -1;
    }

    if (!parse_config(config_abs)) {
        fprintf(stderr, "failed to parse config: %s\n", config_abs);
        return -1;
    }

    /* Route plugin logs to Logs/coverage.log, same as the -fuzz module */
    g_mkdir_with_parents("Logs", 0755);
    log_fp = fopen(log_path, "w");
    if (log_fp) {
        g_log_set_handler(LOG_DOMAIN, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL,
                          log_handler, NULL);
    }

    tb_table = g_hash_table_new(NULL, g_direct_equal);
    trace_head = trace_tail = NULL;
    trace_count = 0;
    prev_loc_exec = 0;

    g_log(LOG_DOMAIN, G_LOG_LEVEL_INFO,
          "coverage plugin loaded: debug=%d block=%d edge=%d trace=%d",
          cfg_debug, cfg_cov_block, cfg_cov_edge, cfg_cov_trace);

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}