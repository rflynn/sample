/* vim: set ts=4 et: */
/*
 * print cpu/mem/network stats once per second
 * optionally watches another process and dies when it does
 */

#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/host_info.h>
#endif

#ifdef __linux__
#include <linux/sysctl.h>
#endif

typedef struct {
    struct {
        struct timespec ts;
        double d;
        char str[32];
    } ts;
    struct {
        long pagesize;
        long pagefree;
        long filepages;
        long size;
        long used;
        long free;
    } mem;
    struct {
        long ticks;
        uint64_t user, sys, idle, nice, total;
    } cpu;
    size_t netcnt;
    struct {
        char iface[32];
        int64_t rxbytes;
        int64_t txbytes;
    } net[16];
} snapshot_t;

static void do_get_ts(struct timespec *ts)
{
#ifdef __MACH__ /* OS X does not have clock_gettime, use clock_get_time */
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_REALTIME, ts);
#endif
}

static void get_ts(snapshot_t *snap)
{
    do_get_ts(&snap->ts.ts);
    snap->ts.d = (double)snap->ts.ts.tv_sec + ((double)snap->ts.ts.tv_nsec / 1000000L);
    snprintf(snap->ts.str, sizeof snap->ts.str, "%lu.%03lu",
        snap->ts.ts.tv_sec, snap->ts.ts.tv_nsec / 1000000L);
}

#ifdef __MACH__
static long get_sysctl(const char *name)
{
    long val;
    size_t len;
    len = sizeof val;
    sysctlbyname(name, &val, &len, NULL, 0);
    return val;
}
#endif

static void get_mem(snapshot_t *snap)
{
#ifdef __MACH__
    FILE *f = popen("vm_stat | grep '^File-backed pages:'", "r");
    char line[128];
    if (fgets(line, sizeof line, f)) {
        if (1 != sscanf(line, "File-backed pages: %ld.", &snap->mem.filepages)) {
            snap->mem.filepages = 0;
        }
    }
    pclose(f);

    if (!snap->mem.size) snap->mem.size = get_sysctl("hw.memsize");
    if (!snap->mem.pagesize) snap->mem.pagesize = get_sysctl("hw.pagesize");
    snap->mem.pagefree = get_sysctl("vm.page_free_count");

    snap->mem.free = (snap->mem.pagefree + snap->mem.filepages) * snap->mem.pagesize;
    snap->mem.used = snap->mem.size - snap->mem.free;
#endif
#ifdef __linux__
    FILE *f = fopen("/proc/meminfo", "r");
    char line[128];

    if (fgets(line, sizeof line, f)) {
        snap->mem.size = 0;
        sscanf(line, "MemTotal: %ld kB", &snap->mem.size);
        snap->mem.size *= 1024;
    }

    if (fgets(line, sizeof line, f)) {
        snap->mem.free = 0;
        sscanf(line, "MemFree: %ld kB", &snap->mem.free);
        snap->mem.free *= 1024;
    }

    snap->mem.used = snap->mem.size - snap->mem.free;

    fclose(f);
#endif
}

static void get_cpu(snapshot_t *snap)
{
#ifdef __MACH__
    kern_return_t status;
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    host_cpu_load_info_data_t cpuload;

    snap->cpu.ticks = sysconf(_SC_CLK_TCK);

    status = host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO,
                             (host_info_t)&cpuload, &count);

    if (status != KERN_SUCCESS) {
        return;
    }

    #define TICK2MSEC(x) ((x) * (1000L / (snap->cpu.ticks)))

    snap->cpu.user = TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_USER]);
    snap->cpu.sys  = TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_SYSTEM]);
    snap->cpu.idle = TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_IDLE]);
    snap->cpu.nice = TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_NICE]);
    snap->cpu.total = snap->cpu.user
                    + snap->cpu.nice
                    + snap->cpu.sys
                    + snap->cpu.idle;
#endif
#ifdef __linux__
    FILE *f = fopen("/proc/stat", "r");
    char line[128];
    // cpu  333883 18436 125736 73090614 45323 1 2663 0 0 0
    if (fgets(line, sizeof line, f)) {
        long user, nice, sys, idle, iowait, irq, softirq;
        if (7 == sscanf(line, "cpu %ld %ld %ld %ld %ld %ld %ld",
            &user, &nice, &sys, &idle, &iowait, &irq, &softirq)) {
            snap->cpu.user = user;
            snap->cpu.sys = sys;
            snap->cpu.idle = idle;
            snap->cpu.nice = nice;
            snap->cpu.total = user + nice + sys + idle + iowait + irq + softirq;
        }
    }
    fclose(f);
#endif
}

static void get_net(snapshot_t *snap)
{
    char line[128];
    /*
     * TODO: figure out how netstat does it and void this crap
     */
#ifdef __MACH__
    const char *cmd = "/usr/sbin/netstat -ibn | /usr/bin/awk '{if (NF+1 == 12){ print $1,$5,$8 }}' | /usr/bin/tail -n +2 | /usr/bin/sort | /usr/bin/uniq";
#endif
#ifdef __linux__
    const char *cmd = "/bin/netstat -in | /usr/bin/awk '{ print $1,$4,$8 }' | tail -n +3";
#endif
    FILE *f = popen(cmd, "r");
    size_t i;
    strcpy(snap->net[0].iface, "all");
    snap->net[0].rxbytes = 0;
    snap->net[0].txbytes = 0;
    for (i = 1; i < sizeof snap->net / sizeof snap->net[0]; i++)
    {
        if (!fgets(line, sizeof line, f)) {
            break;
        }
        if (3 != sscanf(line,
                    "%32s %"SCNd64 " %"SCNd64,
                    snap->net[i].iface,
                    &snap->net[i].rxbytes,
                    &snap->net[i].txbytes)) {
            break;
        }
        snap->net[0].rxbytes += snap->net[i].rxbytes;
        snap->net[0].txbytes += snap->net[i].txbytes;
    }
    snap->netcnt = i;
    pclose(f);
}

static void get_perf(snapshot_t *snap)
{
    get_ts(snap);
    get_mem(snap);
    get_cpu(snap);
    get_net(snap);
}

static long calc_sleep_for(long slept_for,
                           long overheads[10],
                           long *cnt,
                           const snapshot_t *a,
                           const snapshot_t *b)
{
    /*
     * figure out distance between timestamps, and overhead
     * and then calculate how long we should sleep_for
     */
    long udiff = ((b->ts.ts.tv_sec - a->ts.ts.tv_sec) * 1000000L)
                    + ((b->ts.ts.tv_nsec - a->ts.ts.tv_nsec) / 1000L);
    long ohead = udiff - slept_for;
    long sleep_for;
    long ohead_sum = 0;
    long miss_min = udiff, miss_max = 0;
    int i;

    overheads[*cnt % 10] = ohead;
    *cnt += 1;

    /* sum overheads over stored range */
    for (i = 0; i < 10; i++) {
        if (overheads[i] < miss_min) miss_min = overheads[i];
        if (overheads[i] > miss_max) miss_max = overheads[i];
        ohead_sum += overheads[i];
    }
    ohead_sum -= miss_min;
    ohead_sum -= miss_max;

    sleep_for = 1000000 - (ohead_sum / 8);

    if (sleep_for < 0) {
        sleep_for = 0;
    } else if (sleep_for >= 9999999) {
        sleep_for = 999999;
    }

    return sleep_for;
}

static double perf_diff(long slept_for,
                        long oheads[10],
                        long *cnt,
                        const snapshot_t *a,
                        const snapshot_t *b)
{
    const long cpu_total = b->cpu.total - a->cpu.total;
    const long cpu_user  = b->cpu.user  - a->cpu.user;
    const long cpu_sys   = b->cpu.sys   - a->cpu.sys;
    const long cpu_idle  = b->cpu.idle  - a->cpu.idle;

    const float cpu_user_pct = (float)cpu_user / cpu_total;
    const float cpu_sys_pct = (float)cpu_sys / cpu_total;
    const float cpu_idle_pct = (float)cpu_idle / cpu_total;

    const float mem_used_pct = (float)b->mem.used / b->mem.size;

    const unsigned long rxbytes = b->net[0].rxbytes - a->net[0].rxbytes;
    const unsigned long txbytes = b->net[0].txbytes - a->net[0].txbytes;

    const long sleep_for = calc_sleep_for(slept_for, oheads, cnt, a, b);

    printf(
        "%s"
        " %.1f %.1f %.1f"
        " %.1f"
        " %lu %lu\n",
        a->ts.str,
        (1. - cpu_idle_pct) * 100,
        cpu_user_pct * 100,
        cpu_sys_pct * 100,
        mem_used_pct * 100,
        rxbytes,
        txbytes);

    return sleep_for;
}

int main(int argc, char *argv[])
{
    pid_t watchpid = getpid(); /* default: watch self */
    long sleep_for = 990000;
    long oheads[10] = {0};
    long cnt = 0;
    snapshot_t snap1, snap2;
    if (argc == 2) {
        watchpid = strtol(argv[1], NULL, 10);
    }
    printf("ts cpu usr sys mem rx tx\n");
    get_perf(&snap1);
    while (!kill(watchpid, 0)) {
        usleep(sleep_for);
        get_perf(&snap2);
        sleep_for = perf_diff(sleep_for, oheads, &cnt, &snap1, &snap2);
        memcpy(&snap1, &snap2, sizeof snap1);
    }
    return 0;
}
