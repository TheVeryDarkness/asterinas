// SPDX-License-Identifier: MPL-2.0

// Measures what an attached RSM plugin costs on the system-call path, split
// into the per-event cost of entering the extension and the per-call cost of a
// host helper through the trampoline.
//
// The plugin issues `fanout` host-helper calls per observed system call, where
// `fanout` is the first system-call argument. Helper index 0 is one atomic
// increment, so a phase at fanout K costs `dispatch + K * helper`. Timing three
// fanouts (0, 1, 4) and fitting a line separates the two terms.
//
// Phases are interleaved round by round and each phase's best time is kept, so
// emulator drift cannot masquerade as plugin cost. A detached phase brackets
// every round as the control.
#include "syscall_bench_artifact.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

// RSM commands multiplexed through SYS_RSM (matches RsmCmd in rsm.rs).
#define SYS_RSM 500
#define RSM_CMD_LOAD 0
#define RSM_CMD_ATTACH 1
#define RSM_CMD_DETACH 2

// One phase makes ITERATIONS system calls; phases are repeated ROUNDS times.
#define ITERATIONS 100000
#define ROUNDS 5

// The fanouts the artifact implements, and how many it implements.
#define FANOUT_COUNT 3

static const uint64_t fanouts[FANOUT_COUNT] = { 0, 1, 4 };

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// Returns nanoseconds per system call for one phase.
static double time_syscalls(uint64_t fanout)
{
    uint64_t start = now_ns();
    for (long index = 0; index < ITERATIONS; index++) {
        syscall(SYS_getpid, fanout);
    }
    uint64_t end = now_ns();
    return (double)(end - start) / (double)ITERATIONS;
}

static int compare_double(const void *lhs, const void *rhs)
{
    double left = *(const double *)lhs;
    double right = *(const double *)rhs;
    return (left > right) - (left < right);
}

// Returns the median of `count` samples, sorting them in place.
static double median(double *samples, int count)
{
    qsort(samples, count, sizeof(double), compare_double);
    return samples[count / 2];
}

int main(void)
{
    if (syscall(SYS_RSM, RSM_CMD_LOAD, syscall_bench_artifact,
                sizeof(syscall_bench_artifact))
        < 0) {
        perror("RSM_LOAD");
        return 1;
    }

    double detached[ROUNDS];
    double per_fanout[FANOUT_COUNT][ROUNDS];

    for (int round = 0; round < ROUNDS; round++) {
        detached[round] = time_syscalls(0);

        for (int slot = 0; slot < FANOUT_COUNT; slot++) {
            if (syscall(SYS_RSM, RSM_CMD_ATTACH) < 0) {
                perror("RSM_ATTACH");
                return 1;
            }
            per_fanout[slot][round] = time_syscalls(fanouts[slot]);
            syscall(SYS_RSM, RSM_CMD_DETACH);
        }
    }

    double detached_median = median(detached, ROUNDS);
    double cost[FANOUT_COUNT];
    for (int slot = 0; slot < FANOUT_COUNT; slot++) {
        cost[slot] = median(per_fanout[slot], ROUNDS);
    }

    printf("rsm plugin cost, per system call (median of %d rounds):\n", ROUNDS);
    printf("  detached          %8.1fns\n", detached_median);
    for (int slot = 0; slot < FANOUT_COUNT; slot++) {
        printf("  attached fanout %d  %8.1fns\n", (int)fanouts[slot],
               cost[slot]);
    }

    // `cost[k] = dispatch + k * helper`, fitted on the two non-zero fanouts so
    // the zero-fanout phase can check the fit instead of defining it.
    double helper_ns = (cost[2] - cost[1]) / (double)(fanouts[2] - fanouts[1]);
    double dispatch_ns = cost[1] - helper_ns * (double)fanouts[1];
    double predicted_zero = dispatch_ns;
    printf("  fitted dispatch   %8.1fns\n", dispatch_ns);
    printf("  fitted helper     %8.1fns per call\n", helper_ns);
    printf("  fanout-0 residual %8.1fns (predicted %.1f, measured %.1f)\n",
           cost[0] - predicted_zero, predicted_zero, cost[0]);
    printf("  total at fanout 1 %8.1fns (+%.1f%% over detached)\n",
           cost[1] - detached_median,
           100.0 * (cost[1] - detached_median) / detached_median);

    // The plugin must have run: the artifact increments the counter once per
    // helper call, and the fanout-1 and fanout-4 phases issue 1 and 4 calls per
    // observed system call respectively.
    int fd = open("/proc/rsm/stats", O_RDONLY);
    if (fd < 0) {
        perror("open /proc/rsm/stats");
        return 1;
    }
    char stats[256];
    ssize_t length = read(fd, stats, sizeof(stats) - 1);
    close(fd);
    if (length <= 0) {
        fprintf(stderr, "could not read /proc/rsm/stats\n");
        return 1;
    }
    stats[length] = '\0';
    printf("stats: %s", stats);

    unsigned long long counter = 0;
    if (sscanf(stats, "counter=%llu", &counter) != 1) {
        fprintf(stderr, "could not parse the counter from /proc/rsm/stats\n");
        return 1;
    }
    unsigned long long expected = (unsigned long long)ITERATIONS * ROUNDS * 5;
    if (counter < expected) {
        fprintf(stderr, "counter %llu is below the %llu expected increments\n",
                counter, expected);
        return 1;
    }

    // Cost must rise when the plugin is attached; otherwise the measurement is
    // broken, which is different from good news.
    //
    // The fanout slope is reported but not asserted: this kernel runs under
    // QEMU's TCG emulation, where one system call costs tens of microseconds
    // and the difference between one and four helper calls (a few hundred
    // nanoseconds) is inside the noise. A KVM or bare-metal run is needed
    // before the slope means anything.
    if (cost[1] <= detached_median) {
        fprintf(stderr, "attaching the plugin did not cost anything: %.1f %.1f\n",
                detached_median, cost[1]);
        return 1;
    }
    return 0;
}
