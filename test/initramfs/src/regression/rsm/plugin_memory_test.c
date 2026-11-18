// SPDX-License-Identifier: MPL-2.0

// Loads separately compiled Rssembly observers and reads their reported state.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
	RSM_LOAD = 0,
	RSM_READ_STATS = 3,
	RSM_ATTACH_HOOK = 4,
	RSM_DETACH_HOOK = 5,
	RSM_HOOK_STATS = 6,
	RSM_READ_STATE_WORD = 7,
	RSM_UNLOAD = 8,
};

#define CHECK(condition)                                                \
	do {                                                            \
		if (!(condition)) {                                     \
			fprintf(stderr, "FAIL: %s:%d: %s (errno=%d)\n", \
				__FILE__, __LINE__, #condition, errno); \
			exit(1);                                        \
		}                                                       \
	} while (0)

static uint64_t read_hook;
static long rsm(unsigned command, unsigned long a, unsigned long b)
{
	return syscall(500, command, a, b);
}

static uint64_t find_hook(const char *name)
{
	FILE *f = fopen("/proc/rsm/hooks", "r");
	CHECK(f != NULL);
	char *line = NULL;
	size_t capacity = 0;
	uint64_t id = 0;
	while (getline(&line, &capacity, f) >= 0) {
		char *cursor = line;
		char *hex = strsep(&cursor, "\t");
		char *function = strsep(&cursor, "\t");
		if (function && strcmp(function, name) == 0) {
			id = strtoull(hex, NULL, 16);
			break;
		}
	}
	free(line);
	CHECK(fclose(f) == 0 && id != 0);
	return id;
}

static void load(const char *filename)
{
	FILE *f = fopen(filename, "rb");
	CHECK(f != NULL && fseek(f, 0, SEEK_END) == 0);
	long size = ftell(f);
	CHECK(size >= 12 && fseek(f, 0, SEEK_SET) == 0);
	unsigned char *artifact = malloc(size);
	CHECK(artifact && fread(artifact, 1, size, f) == (size_t)size);
	CHECK(fclose(f) == 0);
	CHECK(memcmp(artifact, "RSMPIC\0\0\2\0\0\0", 12) == 0);
	CHECK(rsm(RSM_LOAD, (uintptr_t)artifact, size) == 0);
	free(artifact);
}

struct state_word {
	uint64_t key, index, value;
};

static uint64_t read_word(uint64_t key, uint64_t index)
{
	struct state_word word = { .key = key, .index = index };
	CHECK(rsm(RSM_READ_STATE_WORD, (uintptr_t)&word, 0) == 0);
	return word.value;
}

static void check_word_error(uint64_t key, uint64_t index, int error)
{
	struct state_word word = { .key = key, .index = index };
	errno = 0;
	CHECK(rsm(RSM_READ_STATE_WORD, (uintptr_t)&word, 0) == -1 &&
	      errno == error);
}

static void attach(uint64_t hook, unsigned int phase)
{
	CHECK(rsm(RSM_ATTACH_HOOK, hook, phase) == 0);
}

static void detach(uint64_t hook, unsigned int phase)
{
	CHECK(rsm(RSM_DETACH_HOOK, hook, phase) == 0);
}

static void invalid_read(size_t length)
{
	char byte;
	CHECK(syscall(SYS_read, -1, &byte, length) == -1 && errno == EBADF);
}

enum { READS_PER_THREAD = 32 };
static void *count_reads(void *unused)
{
	(void)unused;
	for (int i = 0; i < READS_PER_THREAD; i++)
		invalid_read(1);
	return NULL;
}

static void check_histogram(void)
{
	load("/test/rsm/read-histogram.rsm.bin");
	check_word_error(0, 0, ENOENT);
	attach(read_hook, 0);
	CHECK(rsm(RSM_UNLOAD, 0, 0) == -1 && errno == EBUSY);
	const size_t sizes[] = { 0, 4, 64, 65, 4096, 4097 };
	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
		invalid_read(sizes[i]);
	pthread_t worker;
	CHECK(pthread_create(&worker, NULL, count_reads, NULL) == 0);
	count_reads(NULL);
	CHECK(pthread_join(worker, NULL) == 0);
	detach(read_hook, 0);
	CHECK(read_word(0, 0) == 1);
	CHECK(read_word(0, 1) == 2 + 2 * READS_PER_THREAD);
	CHECK(read_word(0, 2) == 2 && read_word(0, 3) == 1);
	check_word_error(0, 4, EINVAL);
	attach(read_hook, 0);
	invalid_read(4097);
	CHECK(read_word(0, 3) == 2);
	puts("PASS: read-size histogram counts both threads and survives detach");
}

static void check_outcomes(void)
{
	// The histogram still owns the entry attachment. This second program
	// deliberately uses the same numeric key for a different array.
	load("/test/rsm/read-outcomes.rsm.bin");
	check_word_error(0, 0, ENOENT);
	attach(read_hook, 1);
	int fds[2];
	char byte;
	CHECK(pipe(fds) == 0 && write(fds[1], "x", 1) == 1);
	CHECK(read(fds[0], &byte, 1) == 1 && byte == 'x');
	for (int i = 0; i < 4; i++)
		invalid_read(1);
	detach(read_hook, 0);
	detach(read_hook, 1);
	CHECK(close(fds[0]) == 0 && close(fds[1]) == 0);
	CHECK(read_word(0, 0) == 1 && read_word(0, 1) == 4);
	check_word_error(0, 2, EINVAL);
	FILE *log = fopen("/proc/rsm/log", "r");
	CHECK(log != NULL);
	char messages[4097];
	size_t n = fread(messages, 1, sizeof(messages) - 1, log);
	CHECK(!ferror(log) && fclose(log) == 0);
	messages[n] = '\0';
	const char *alert = strstr(messages, "three failed reads\n");
	CHECK(alert && !strstr(alert + 1, "three failed reads\n"));
	CHECK(rsm(RSM_UNLOAD, 0, 0) == 0);
	check_word_error(0, 0, ENOENT);
	CHECK(rsm(RSM_UNLOAD, 0, 0) == -1 && errno == ENOENT);
	load("/test/rsm/read-outcomes.rsm.bin");
	check_word_error(0, 0, ENOENT);
	CHECK(rsm(RSM_UNLOAD, 0, 0) == 0);
	puts("PASS: overlapping programs isolate key zero, alert once, and reload empty");
}

static void check_latency(void)
{
	load("/test/rsm/read-latency.rsm.bin");
	attach(read_hook, 0);
	attach(read_hook, 1);
	// More calls than the number of simultaneously available map allocations.
	for (int i = 0; i < 48; i++)
		invalid_read(1);
	detach(read_hook, 0);
	detach(read_hook, 1);
	CHECK(read_word(0, 0) == 48 && read_word(0, 1) > 0 &&
	      read_word(0, 2) == 0);
	CHECK(rsm(RSM_UNLOAD, 0, 0) == 0);
	puts("PASS: paired 48 reads by invocation ID and reused released map storage");
}

static void check_heap_snapshot(void)
{
	load("/test/rsm/heap-snapshot.rsm.bin");
	attach(read_hook, 0);
	const size_t sizes[] = { 3, 7, 11, 300, 9, 10, 13, 17, 19 };
	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
		invalid_read(sizes[i]);
	detach(read_hook, 0);
	// Seven sizes followed by the cursor, packed little-endian by the host.
	CHECK(read_word(0, 0) == UINT64_C(0x020d0a09ff0b1311));
	CHECK(rsm(RSM_UNLOAD, 0, 0) == 0);
	puts("PASS: restored and saved the entire Rust allocation across nine callbacks");
}

struct hook_stats {
	uint64_t hook;
	uint32_t phase, reserved;
	uint64_t invocations, skipped, traps;
};

static struct hook_stats entry_stats(void)
{
	struct hook_stats stats = { .hook = read_hook, .phase = 0 };
	CHECK(rsm(RSM_HOOK_STATS, (uintptr_t)&stats, 0) == 0);
	return stats;
}

static void check_allocator(void)
{
	load("/test/rsm/allocator.rsm.bin");
	struct hook_stats before = entry_stats();
	attach(read_hook, 0);
	for (int i = 0; i < 16; i++)
		invalid_read(1);
	// The observer requests 513 bytes in a 512-byte lane for this input.
	invalid_read(2);
	for (int i = 0; i < 16; i++)
		invalid_read(1);
	detach(read_hook, 0);
	struct hook_stats after = entry_stats();
	CHECK(after.invocations == before.invocations + 33);
	CHECK(after.skipped == before.skipped &&
	      after.traps == before.traps + 1);
	struct {
		uint64_t counter, invocations;
	} stats;
	CHECK(rsm(RSM_READ_STATS, (uintptr_t)&stats, 0) == 0 &&
	      stats.counter == 32);
	CHECK(read_word(0, 0) == 32 * ((read_hook & 255) | 1));
	CHECK(rsm(RSM_UNLOAD, 0, 0) == 0);
	puts("PLUGIN_ALLOCATOR_QEMU_PASS: 32 checked byte round trips, one allocation refused, subsequent callbacks succeeded");
}

#include "showcase_bind_outcomes.h"
#include "showcase_futex_wait.h"
#include "showcase_open_intent.h"
#include "showcase_page_faults.h"

static void check_showcase_driver(void)
{
	// Resolve one map by its hook name and request a second, unused map.
	const char *udp =
		"aster_core::net::socket::ip::datagram::<DatagramSocket as Socket>::bind";
	char selector[128], report[160];
	CHECK(snprintf(selector, sizeof(selector), "@%s", udp) <
	      (int)sizeof(selector));
	CHECK(snprintf(report, sizeof(report), "map %s: 2 3\n", selector) <
	      (int)sizeof(report));
	int output[2];
	CHECK(pipe(output) == 0);
	pid_t child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		close(output[0]);
		CHECK(dup2(output[1], STDOUT_FILENO) == STDOUT_FILENO);
		close(output[1]);
		execl("/test/rsm/rsm-observe", "rsm-observe",
		      "/test/rsm/bind-outcomes.rsm.bin", "--attach", "return",
		      udp, "--read", selector, "2", "--read", "0", "1", "--",
		      "/test/rsm/plugin_memory_test", "bind-workload",
		      (char *)NULL);
		_exit(127);
	}
	CHECK(close(output[1]) == 0);
	FILE *stream = fdopen(output[0], "r");
	CHECK(stream != NULL);
	int counts = 0, missing = 0, workload = 0;
	char *line = NULL;
	size_t capacity = 0;
	while (getline(&line, &capacity, stream) >= 0) {
		fputs(line, stdout);
		counts += strcmp(line, report) == 0;
		missing += strcmp(line, "map 0: no samples\n") == 0;
		workload += strcmp(line, "bind workload complete\n") == 0;
	}
	free(line);
	CHECK(!ferror(stream) && fclose(stream) == 0);
	int status;
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 23);
	CHECK(counts == 1 && missing == 1 && workload == 1);
	check_word_error(0, 0, ENOENT);
	CHECK(rsm(RSM_UNLOAD, 0, 0) == -1 && errno == ENOENT);
	puts("PASS: userspace controller reported named maps and returned the workload's exit status");
}

int main(int argc, char **argv)
{
	CHECK(argc == 2);
	if (strcmp(argv[1], "bind-workload") == 0) {
		exercise_bind_conflicts(SOCK_DGRAM, 3);
		puts("bind workload complete");
		return 23;
	}
	if (strcmp(argv[1], "showcases") == 0) {
		check_open_intent();
		check_bind_outcomes();
		check_page_faults();
		check_futex_wait();
		check_showcase_driver();
		puts("RSM_SHOWCASES_QEMU_PASS");
		return 0;
	}
	read_hook = find_hook("aster_core::syscall::read::sys_read");
	if (strcmp(argv[1], "maps") == 0) {
		check_histogram();
		check_outcomes();
		check_latency();
		check_heap_snapshot();
		puts("PLUGIN_STATE_QEMU_PASS");
	} else {
		CHECK(strcmp(argv[1], "allocator") == 0);
		check_allocator();
	}
	return 0;
}
