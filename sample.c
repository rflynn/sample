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
    struct {
        double all_mb;
        int64_t rdbytes;
        int64_t wrbytes;
    } disk;
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

static void get_disk(snapshot_t *snap)
{
#ifdef __linux__
    FILE *f = open("cat /proc/diskstats | awk '{print $3,$6,$10}' | grep -v ' 0 0$'", "r");
    char line[128];
    int64_t bytes_rd_total = 0, bytes_wr_total = 0;
    while (fgets(line, sizeof line, f))
    {
        long sec_rd, sec_wr;
        /*
         * ref: https://www.kernel.org/doc/Documentation/ABI/testing/procfs-diskstats
         1 - major number
         2 - minor mumber
         3 - device name
         4 - reads completed successfully
         5 - reads merged
         6 - sectors read
         7 - time spent reading (ms)
         8 - writes completed
         9 - writes merged
        10 - sectors written
        11 - time spent writing (ms)
        12 - I/Os currently in progress
        13 - time spent doing I/Os (ms)
        14 - weighted time spent doing I/Os (ms)
        example: 253       0 vda 271030 5 10842162 110468 1992433 698668 41103296 1604644 0 537832 1713740
         */
        if (2 == sscanf(line, "%*d %*d %*s %*ld %*ld %ld %*ld %*ld %*ld %ld", &sec_rd, &sec_wr)) {
            long bytes_rd, bytes_wr;
            bytes_rd = sec_rd * 512; /* FIXME: assume block size */
            bytes_wr = sec_wr * 512; /* FIXME: assume block size */
            bytes_rd_total += bytes_rd;
            bytes_wr_total += bytes_wr;
            snap->disk.rdbytes = bytes_rd_total;
            snap->disk.wrbytes = bytes_wr_total;
            snap->disk.totalbytes = bytes_rd_total + bytes_wr_total;
        }
    }
    fclose(f);
#endif
#ifdef __MACH__
    /*
    $ iostat -d -I
          disk0
    KB/t xfrs   MB
   39.17 598988 22913.05
    */
    FILE *f = popen("/usr/sbin/iostat -d -I", "r");
    if (f) {
        char line[256];
        /* skip 2 header lines */
        fgets(line, sizeof line, f);
        fgets(line, sizeof line, f);
        /* TODO: handle more than just the first device */
        if (fgets(line, sizeof line, f)) {
            double mb = 0;
            if (1 == sscanf(line, "%*lf %*ld %lf", &mb)) {
                snap->disk.all_mb = mb;
            }
        }
        pclose(f);
    }
#endif
}

static void take_snap(snapshot_t *snap)
{
    get_ts(snap);
    get_mem(snap);
    get_cpu(snap);
    get_net(snap);
    get_disk(snap);
}

static void on_snap(const snapshot_t *a,
                    const snapshot_t *b)
{
    const long cpu_total = b->cpu.total - a->cpu.total;
    const long cpu_user  = b->cpu.user  - a->cpu.user;
    const long cpu_sys   = b->cpu.sys   - a->cpu.sys;
    const long cpu_idle  = b->cpu.idle  - a->cpu.idle;

    const float cpu_user_pct = (float)cpu_user / cpu_total;
    const float cpu_sys_pct  = (float)cpu_sys / cpu_total;
    const float cpu_idle_pct = (float)cpu_idle / cpu_total;

    const float mem_used_pct = (float)b->mem.used / b->mem.size;

    const double        diskallmb   = b->disk.all_mb  - a->disk.all_mb;
    const unsigned long diskrdbytes = b->disk.rdbytes - a->disk.rdbytes;
    const unsigned long diskwrbytes = b->disk.wrbytes - a->disk.wrbytes;

    const unsigned long rxbytes = b->net[0].rxbytes - a->net[0].rxbytes;
    const unsigned long txbytes = b->net[0].txbytes - a->net[0].txbytes;

    float cpu_busy_pct = 1. - cpu_idle_pct;
    if (cpu_busy_pct < cpu_user_pct + cpu_sys_pct) {
        cpu_busy_pct = cpu_user_pct + cpu_sys_pct;
    }

    printf(
        "%s"
        " %.1f %.1f %.1f"
        " %.1f"
        " %.1f %lu %lu"
        " %lu %lu\n",
        a->ts.str,
        cpu_busy_pct * 100,
        cpu_user_pct * 100,
        cpu_sys_pct * 100,
        mem_used_pct * 100,
        diskallmb,
        diskrdbytes,
        diskwrbytes,
        rxbytes,
        txbytes);
}

static snapshot_t snap1, snap2;

void timer_handler(int signum)
{
    take_snap(&snap2);
    on_snap(&snap1, &snap2);
    snap1 = snap2;
}

int main(int argc, char *argv[])
{
    pid_t watchpid = getpid(); /* default: watch self */
    struct sigaction sa;
    struct itimerval timer;

    if (argc == 2) {
        watchpid = strtol(argv[1], NULL, 10);
    }

    /* explicit line-buffering so 'tee' and friends work as expected */
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = &timer_handler;
    sigaction(SIGALRM, &sa, NULL);
    timer.it_value.tv_sec = 1;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 1;
    timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &timer, NULL);

    printf("ts cpu usr sys mem disktotal diskrd diskwr netrx nettx\n");
    take_snap(&snap1);

    while (!kill(watchpid, 0)) {
        usleep(1000000);
    }
    return 0;
}
