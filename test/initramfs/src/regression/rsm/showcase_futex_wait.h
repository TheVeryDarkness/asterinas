/* SPDX-License-Identifier: MPL-2.0 */

#ifndef SHOWCASE_FUTEX_WAIT_H
#define SHOWCASE_FUTEX_WAIT_H

#include <linux/futex.h>
#include <time.h>

struct futex_workload {
	uint32_t word;
	int control;
	int ready;
};

static void *wake_futex_waiter(void *arg)
{
	struct futex_workload *work = arg;
	char signal;
	CHECK(write(work->ready, "r", 1) == 1);
	CHECK(read(work->control, &signal, 1) == 1);

	struct timespec now;
	CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
	time_t deadline = now.tv_sec + 10;
	for (;;) {
		long woke = syscall(SYS_futex, &work->word, FUTEX_WAKE_PRIVATE,
				    1, NULL, NULL, 0);
		CHECK(woke >= 0);
		if (woke == 1)
			break;
		CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
		      now.tv_sec < deadline);
		usleep(1000);
	}
	// Keep thread teardown outside the observation interval.
	CHECK(read(work->control, &signal, 1) == 1);
	return NULL;
}

static void check_futex_wait(void)
{
	uint64_t hook = find_hook(
		"aster_core::process::posix_thread::futex::futex_wait");
	load("/test/rsm/futex-wait.rsm.bin");
	int control[2], ready[2];
	CHECK(pipe(control) == 0 && pipe(ready) == 0);
	struct futex_workload work = { .control = control[0],
				       .ready = ready[1] };
	pthread_t worker;
	char signal;
	CHECK(pthread_create(&worker, NULL, wake_futex_waiter, &work) == 0);
	CHECK(read(ready[0], &signal, 1) == 1);

	attach(hook, 0);
	attach(hook, 1);
	struct timespec timeout = { .tv_sec = 10 };
	CHECK(syscall(SYS_futex, &work.word, FUTEX_WAIT_PRIVATE, 1, &timeout,
		      NULL, 0) == -1 &&
	      errno == EAGAIN);
	CHECK(write(control[1], "w", 1) == 1);
	CHECK(syscall(SYS_futex, &work.word, FUTEX_WAIT_PRIVATE, 0, &timeout,
		      NULL, 0) == 0);
	detach(hook, 1);
	detach(hook, 0);

	CHECK(write(control[1], "q", 1) == 1);
	CHECK(pthread_join(worker, NULL) == 0);
	CHECK(close(control[0]) == 0 && close(control[1]) == 0);
	CHECK(close(ready[0]) == 0 && close(ready[1]) == 0);

	uint64_t buckets[4];
	uint64_t successes = 0;
	for (unsigned int i = 0; i < 4; i++) {
		buckets[i] = read_word(0, i);
		successes += buckets[i];
	}
	uint64_t errors = read_word(0, 4), unmatched = read_word(0, 5);
	printf("futex-wait: <100us=%" PRIu64 " 100us-<1ms=%" PRIu64
	       " 1ms-<10ms=%" PRIu64 " >=10ms=%" PRIu64 " errors=%" PRIu64
	       " unmatched=%" PRIu64 "\n",
	       buckets[0], buckets[1], buckets[2], buckets[3], errors,
	       unmatched);
	CHECK(successes == 1 && errors == 1 && unmatched == 0);
	CHECK(rsm(RSM_UNLOAD, 0, 0) == 0);
}

#endif
