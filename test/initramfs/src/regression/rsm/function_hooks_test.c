// SPDX-License-Identifier: MPL-2.0

// The embedded v1 benchmark and optional compiled v2 observer exercise the
// same hook interface across two generations of the native artifact format.
#include "syscall_bench_artifact.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SYS_RSM 500
#define RSM_LOAD 0
#define RSM_ATTACH 1
#define RSM_DETACH 2
#define RSM_READ_STATS 3
#define RSM_ATTACH_HOOK 4
#define RSM_DETACH_HOOK 5
#define RSM_READ_HOOK_STATS 6
#define HOOK_ENTRY 0
#define HOOK_RETURN 1
#define CONTROLLED_CALLS 16
#define REATTACH_ROUNDS 32
#define ENTRY_WAIT_ROUNDS 10000

#define CHECK(condition)                                                \
	do {                                                            \
		if (!(condition)) {                                     \
			fprintf(stderr, "FAIL: %s:%d: %s (errno=%d)\n", \
				__FILE__, __LINE__, #condition, errno); \
			exit(EXIT_FAILURE);                             \
		}                                                       \
	} while (0)

struct hook_stats {
	uint64_t hook_id;
	uint32_t phase;
	uint32_t reserved;
	uint64_t invocations;
	uint64_t skipped;
	uint64_t traps;
};

struct program_stats {
	uint64_t counter;
	uint64_t invocations;
};

static uint64_t getpid_hook;
static uint64_t read_hook;
static atomic_int worker_failed;
static atomic_int worker_started;
static atomic_int worker_stop;
static atomic_uint worker_calls;
static atomic_int blocked_read_start;
static atomic_int blocked_read_failed;

static long rsm(unsigned int command, unsigned long argument1,
		unsigned long argument2)
{
	return syscall(SYS_RSM, command, argument1, argument2);
}

static struct hook_stats hook_stats(uint64_t hook_id, uint32_t phase)
{
	struct hook_stats stats = { .hook_id = hook_id, .phase = phase };
	CHECK(rsm(RSM_READ_HOOK_STATS, (uintptr_t)&stats, 0) == 0);
	return stats;
}

static uint64_t program_counter(void)
{
	struct program_stats stats;
	CHECK(rsm(RSM_READ_STATS, (uintptr_t)&stats, 0) == 0);
	return stats.counter;
}

static void cleanup(void)
{
	if (getpid_hook) {
		rsm(RSM_DETACH_HOOK, getpid_hook, HOOK_ENTRY);
		rsm(RSM_DETACH_HOOK, getpid_hook, HOOK_RETURN);
	}
	if (read_hook) {
		rsm(RSM_DETACH_HOOK, read_hook, HOOK_ENTRY);
		rsm(RSM_DETACH_HOOK, read_hook, HOOK_RETURN);
	}
	rsm(RSM_DETACH, 0, 0);
}

static void discover_hooks(void)
{
	static const char *const prefixes[] = {
		"aster_core::syscall::", "aster_core::fs::",
		"aster_core::net::",	 "aster_core::process::",
		"aster_core::vm::",	 "aster_core::ipc::",
	};
	unsigned int counts[sizeof(prefixes) / sizeof(prefixes[0])] = { 0 };
	FILE *catalog = fopen("/proc/rsm/hooks", "r");
	CHECK(catalog != NULL);
	char *line = NULL;
	size_t capacity = 0;
	size_t total = 0;
	while (getline(&line, &capacity, catalog) >= 0) {
		if (line[0] == '#' || line[0] == '\n')
			continue;
		char *cursor = line;
		char *id_text = strsep(&cursor, "\t");
		char *name = strsep(&cursor, "\t");
		char *entry_fields = strsep(&cursor, "\t");
		CHECK(name != NULL && entry_fields != NULL && cursor != NULL);
		errno = 0;
		char *end = NULL;
		uint64_t id = strtoull(id_text, &end, 16);
		CHECK(errno == 0 && end != id_text && *end == '\0' && id != 0);
		for (size_t index = 0;
		     index < sizeof(counts) / sizeof(counts[0]); index++) {
			if (strncmp(name, prefixes[index],
				    strlen(prefixes[index])) == 0)
				counts[index]++;
		}
		if (strcmp(name, "aster_core::syscall::getpid::sys_getpid") ==
		    0) {
			CHECK(getpid_hook == 0);
			getpid_hook = id;
		}
		if (strcmp(name, "aster_core::syscall::read::sys_read") == 0) {
			CHECK(read_hook == 0);
			read_hook = id;
			CHECK(strstr(entry_fields, "buf_len:usize") != NULL);
		}
		total++;
	}
	CHECK(!ferror(catalog));
	free(line);
	CHECK(fclose(catalog) == 0);
	CHECK(getpid_hook != 0 && read_hook != 0 && total >= 50);
	for (size_t index = 0; index < sizeof(counts) / sizeof(counts[0]);
	     index++) {
		CHECK(counts[index] > 0);
		printf("  %s %u hooks\n", prefixes[index], counts[index]);
	}
	printf("PASS: discovered %zu function hooks across six subsystems\n",
	       total);
}

static void check_management_errors(void)
{
	errno = 0;
	CHECK(rsm(RSM_ATTACH_HOOK, getpid_hook, 2) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(rsm(RSM_ATTACH_HOOK, 0, HOOK_ENTRY) == -1 && errno == ENOENT);
	CHECK(rsm(RSM_ATTACH_HOOK, getpid_hook, HOOK_ENTRY) == 0);
	errno = 0;
	CHECK(rsm(RSM_ATTACH_HOOK, getpid_hook, HOOK_ENTRY) == -1 &&
	      errno == EBUSY);
	CHECK(rsm(RSM_DETACH_HOOK, getpid_hook, HOOK_ENTRY) == 0);
	puts("PASS: invalid phase, unknown hook, and duplicate attachment rejected");
}

static void check_getpid_hooks(void)
{
	CHECK(rsm(RSM_ATTACH_HOOK, getpid_hook, HOOK_ENTRY) == 0);
	CHECK(rsm(RSM_ATTACH_HOOK, getpid_hook, HOOK_RETURN) == 0);
	struct hook_stats entry_before = hook_stats(getpid_hook, HOOK_ENTRY);
	struct hook_stats return_before = hook_stats(getpid_hook, HOOK_RETURN);
	uint64_t counter_before = program_counter();
	for (int index = 0; index < CONTROLLED_CALLS; index++)
		CHECK(syscall(SYS_getpid) > 0);
	struct hook_stats entry_after = hook_stats(getpid_hook, HOOK_ENTRY);
	struct hook_stats return_after = hook_stats(getpid_hook, HOOK_RETURN);
	CHECK(entry_after.invocations - entry_before.invocations ==
	      CONTROLLED_CALLS);
	CHECK(return_after.invocations - return_before.invocations ==
	      CONTROLLED_CALLS);
	CHECK(entry_after.skipped == entry_before.skipped);
	CHECK(return_after.skipped == return_before.skipped);
	CHECK(entry_after.traps == entry_before.traps);
	CHECK(return_after.traps == return_before.traps);
	CHECK(program_counter() - counter_before == CONTROLLED_CALLS);
	CHECK(rsm(RSM_DETACH_HOOK, getpid_hook, HOOK_ENTRY) == 0);
	CHECK(rsm(RSM_DETACH_HOOK, getpid_hook, HOOK_RETURN) == 0);
	entry_before = hook_stats(getpid_hook, HOOK_ENTRY);
	return_before = hook_stats(getpid_hook, HOOK_RETURN);
	counter_before = program_counter();
	for (int index = 0; index < CONTROLLED_CALLS; index++)
		CHECK(syscall(SYS_getpid) > 0);
	entry_after = hook_stats(getpid_hook, HOOK_ENTRY);
	return_after = hook_stats(getpid_hook, HOOK_RETURN);
	CHECK(entry_after.invocations == entry_before.invocations);
	CHECK(return_after.invocations == return_before.invocations);
	CHECK(program_counter() == counter_before);
	puts("PASS: independent entry/return hooks execute RSM and detach stops new calls");
}

static void check_error_return(void)
{
	CHECK(rsm(RSM_ATTACH_HOOK, read_hook, HOOK_ENTRY) == 0);
	CHECK(rsm(RSM_ATTACH_HOOK, read_hook, HOOK_RETURN) == 0);
	struct hook_stats entry_before = hook_stats(read_hook, HOOK_ENTRY);
	struct hook_stats return_before = hook_stats(read_hook, HOOK_RETURN);
	uint64_t counter_before = program_counter();
	char byte;
	for (int index = 0; index < CONTROLLED_CALLS; index++) {
		errno = 0;
		CHECK(syscall(SYS_read, -1, &byte, 1) == -1 && errno == EBADF);
	}
	struct hook_stats entry_after = hook_stats(read_hook, HOOK_ENTRY);
	struct hook_stats return_after = hook_stats(read_hook, HOOK_RETURN);
	CHECK(entry_after.invocations - entry_before.invocations ==
	      CONTROLLED_CALLS);
	CHECK(return_after.invocations - return_before.invocations ==
	      CONTROLLED_CALLS);
	CHECK(entry_after.traps == entry_before.traps);
	CHECK(return_after.traps == return_before.traps);
	CHECK(program_counter() - counter_before == CONTROLLED_CALLS);
	CHECK(rsm(RSM_DETACH_HOOK, read_hook, HOOK_ENTRY) == 0);
	CHECK(rsm(RSM_DETACH_HOOK, read_hook, HOOK_RETURN) == 0);
	puts("PASS: early error propagation fires normal-return hooks and preserves errno");
}

static void *invoke_getpid(void *unused)
{
	(void)unused;
	atomic_store(&worker_started, 1);
	while (!atomic_load(&worker_stop)) {
		if (syscall(SYS_getpid) <= 0)
			atomic_store(&worker_failed, 1);
		atomic_fetch_add(&worker_calls, 1);
	}
	return NULL;
}

static void check_concurrent_detach(void)
{
	pthread_t worker;
	CHECK(pthread_create(&worker, NULL, invoke_getpid, NULL) == 0);
	while (!atomic_load(&worker_started))
		sched_yield();
	for (int index = 0; index < REATTACH_ROUNDS; index++) {
		CHECK(rsm(RSM_ATTACH_HOOK, getpid_hook, HOOK_RETURN) == 0);
		CHECK(syscall(SYS_getpid) > 0);
		sched_yield();
		CHECK(rsm(RSM_DETACH_HOOK, getpid_hook, HOOK_RETURN) == 0);
	}
	atomic_store(&worker_stop, 1);
	CHECK(pthread_join(worker, NULL) == 0);
	CHECK(atomic_load(&worker_failed) == 0);
	CHECK(atomic_load(&worker_calls) > 0);
	struct hook_stats before = hook_stats(getpid_hook, HOOK_RETURN);
	for (int index = 0; index < CONTROLLED_CALLS; index++)
		CHECK(syscall(SYS_getpid) > 0);
	struct hook_stats after = hook_stats(getpid_hook, HOOK_RETURN);
	CHECK(after.invocations == before.invocations);
	CHECK(after.traps == 0);
	puts("PASS: concurrent calls survive repeated detach and reattach");
}

static void *blocking_read(void *argument)
{
	int fd = *(int *)argument;
	while (!atomic_load(&blocked_read_start))
		sched_yield();
	char byte = 0;
	if (syscall(SYS_read, fd, &byte, 1) != 1 || byte != 'x')
		atomic_store(&blocked_read_failed, 1);
	return NULL;
}

static void check_pending_return_generation(void)
{
	int pipe_fds[2];
	CHECK(pipe(pipe_fds) == 0);
	pthread_t worker;
	CHECK(pthread_create(&worker, NULL, blocking_read, &pipe_fds[0]) == 0);
	CHECK(rsm(RSM_ATTACH_HOOK, read_hook, HOOK_ENTRY) == 0);
	CHECK(rsm(RSM_ATTACH_HOOK, read_hook, HOOK_RETURN) == 0);
	struct hook_stats entry_before = hook_stats(read_hook, HOOK_ENTRY);
	struct hook_stats return_before = hook_stats(read_hook, HOOK_RETURN);
	atomic_store(&blocked_read_start, 1);
	struct hook_stats entry_after;
	int round;
	for (round = 0; round < ENTRY_WAIT_ROUNDS; round++) {
		entry_after = hook_stats(read_hook, HOOK_ENTRY);
		if (entry_after.invocations > entry_before.invocations)
			break;
		sched_yield();
	}
	CHECK(round < ENTRY_WAIT_ROUNDS);
	CHECK(entry_after.invocations == entry_before.invocations + 1);
	// The empty pipe keeps this call pending until after replacement. No
	// timeout or scheduler speed assumption determines which generation ran.
	CHECK(hook_stats(read_hook, HOOK_RETURN).invocations ==
	      return_before.invocations);
	CHECK(rsm(RSM_DETACH_HOOK, read_hook, HOOK_RETURN) == 0);
	CHECK(rsm(RSM_ATTACH_HOOK, read_hook, HOOK_RETURN) == 0);
	CHECK(write(pipe_fds[1], "x", 1) == 1);
	CHECK(pthread_join(worker, NULL) == 0);
	CHECK(atomic_load(&blocked_read_failed) == 0);
	struct hook_stats return_after = hook_stats(read_hook, HOOK_RETURN);
	CHECK(return_after.invocations == return_before.invocations);
	CHECK(return_after.skipped == return_before.skipped + 1);
	CHECK(return_after.traps == return_before.traps);
	errno = 0;
	CHECK(syscall(SYS_read, -1, pipe_fds, 1) == -1 && errno == EBADF);
	CHECK(hook_stats(read_hook, HOOK_RETURN).invocations ==
	      return_before.invocations + 1);
	CHECK(rsm(RSM_DETACH_HOOK, read_hook, HOOK_ENTRY) == 0);
	CHECK(rsm(RSM_DETACH_HOOK, read_hook, HOOK_RETURN) == 0);
	CHECK(close(pipe_fds[0]) == 0);
	CHECK(close(pipe_fds[1]) == 0);
	puts("PASS: blocking function holds no CPU guard and old return cannot retarget replacement");
}

static void check_legacy_attachment(void)
{
	CHECK(rsm(RSM_ATTACH, 0, 0) == 0);
	uint64_t before = program_counter();
	for (int index = 0; index < CONTROLLED_CALLS; index++)
		CHECK(syscall(SYS_getpid, 1) > 0);
	uint64_t after = program_counter();
	CHECK(rsm(RSM_DETACH, 0, 0) == 0);
	CHECK(after - before >= CONTROLLED_CALLS);
	puts("PASS: legacy syscall attachment still executes the verified artifact");
}

static void check_v2_observer(const char *path)
{
	FILE *file = fopen(path, "rb");
	CHECK(file != NULL && fseek(file, 0, SEEK_END) == 0);
	long size = ftell(file);
	CHECK(size >= 12 && fseek(file, 0, SEEK_SET) == 0);
	unsigned char *artifact = malloc(size);
	CHECK(artifact != NULL);
	CHECK(fread(artifact, 1, size, file) == (size_t)size);
	CHECK(fclose(file) == 0);
	CHECK(memcmp(artifact, "RSMPIC\0\0\2\0\0\0", 12) == 0);
	CHECK(rsm(RSM_LOAD, (uintptr_t)artifact, size) == 0);
	free(artifact);

	int log = open("/proc/rsm/log", O_WRONLY);
	CHECK(log >= 0 && write(log, "\n", 1) >= 0 && close(log) == 0);
	struct hook_stats entry = hook_stats(read_hook, HOOK_ENTRY);
	struct hook_stats ret = hook_stats(read_hook, HOOK_RETURN);
	uint64_t counter = program_counter();
	CHECK(rsm(RSM_ATTACH_HOOK, read_hook, HOOK_ENTRY) == 0);
	CHECK(rsm(RSM_ATTACH_HOOK, read_hook, HOOK_RETURN) == 0);
	char byte;
	errno = 0;
	CHECK(syscall(SYS_read, -1, &byte, 1) == -1 && errno == EBADF);
	CHECK(rsm(RSM_DETACH_HOOK, read_hook, HOOK_RETURN) == 0);
	CHECK(rsm(RSM_DETACH_HOOK, read_hook, HOOK_ENTRY) == 0);
	struct hook_stats after_entry = hook_stats(read_hook, HOOK_ENTRY);
	struct hook_stats after_ret = hook_stats(read_hook, HOOK_RETURN);
	CHECK(after_entry.invocations == entry.invocations + 1);
	CHECK(after_ret.invocations == ret.invocations + 1);
	CHECK(after_entry.skipped == entry.skipped &&
	      after_entry.traps == entry.traps);
	CHECK(after_ret.skipped == ret.skipped && after_ret.traps == ret.traps);
	CHECK(program_counter() == counter + 1);

	// The observer emits these literals only for the expected phase and payload.
	static const char expected[] = "rsm-v2-entry\nrsm-v2-return\n";
	char messages[sizeof(expected)];
	file = fopen("/proc/rsm/log", "r");
	CHECK(file != NULL);
	CHECK(fread(messages, 1, sizeof(messages), file) ==
	      sizeof(expected) - 1);
	CHECK(!ferror(file) &&
	      memcmp(messages, expected, sizeof(expected) - 1) == 0);
	CHECK(fclose(file) == 0);
	printf("FUNCTION_HOOKS_V2_OBSERVER_PASS: %ld bytes, rsm-v2-entry + rsm-v2-return, entry=1 return=1 counter_delta=1\n",
	       size);
}

int main(int argc, char *argv[])
{
	CHECK(argc == 1 || argc == 2);
	CHECK(atexit(cleanup) == 0);
	discover_hooks();
	CHECK(rsm(RSM_LOAD, (uintptr_t)syscall_bench_artifact,
		  sizeof(syscall_bench_artifact)) == 0);
	check_management_errors();
	check_getpid_hooks();
	check_error_return();
	check_concurrent_detach();
	check_pending_return_generation();
	check_legacy_attachment();
	if (argc == 2)
		check_v2_observer(argv[1]);
	puts("FUNCTION_HOOKS_TEST_PASS");
	return 0;
}
