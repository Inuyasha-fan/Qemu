#include "qemu/osdep.h"
#include "cpu.h"
#include "monitor/monitor.h"
#include "monitor/hmp-target.h"
#include "monitor/hmp.h"

void hmp_info_asid(Monitor *mon, const QDict *qdict)
{
    CPUArchState *env = mon_get_cpu_env(mon);

    if (!env) {
        monitor_printf(mon, "No CPU available\n");
        return;
    }

    CPUMIPSState *mips_env = (CPUMIPSState *)env;
    uint64_t asid = mips_env->CP0_EntryHi & mips_env->CP0_EntryHi_ASID_mask;

    monitor_printf(mon, "ASID: 0x%02" PRIx64 " (%" PRIu64 ")\n", asid, asid);
}

const MonitorDef monitor_defs[] = {
    { NULL },
};

const MonitorDef *target_monitor_defs(void)
{
    return monitor_defs;
}
