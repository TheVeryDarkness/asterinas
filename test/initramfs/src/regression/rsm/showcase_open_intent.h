// SPDX-License-Identifier: MPL-2.0

#ifndef RSM_SHOWCASE_OPEN_INTENT_H
#define RSM_SHOWCASE_OPEN_INTENT_H

#include <fcntl.h>

static void check_open_intent(void)
{
	const uint64_t hook =
		find_hook("aster_core::syscall::open::sys_openat");
	char dir[] = "/tmp/rsm-opens-XXXXXX";
	CHECK(mkdtemp(dir) != NULL);
	int dirfd = open(dir, O_RDONLY | O_DIRECTORY);
	CHECK(dirfd >= 0);
	load("/test/rsm/open-intent.rsm.bin");

	// A return without its entry must stay out of the classified totals.
	attach(hook, 1);
	CHECK(syscall(SYS_openat, dirfd, "missing", O_RDONLY, 0) == -1 &&
	      errno == ENOENT);
	attach(hook, 0);

	const int create = O_WRONLY | O_CREAT | O_EXCL;
	long fd = syscall(SYS_openat, dirfd, "data", create, 0600);
	CHECK(fd >= 0 && close(fd) == 0);
	CHECK(syscall(SYS_openat, dirfd, "data", create, 0600) == -1 &&
	      errno == EEXIST);
	const int flags[] = { O_RDONLY, O_RDONLY | O_CLOEXEC, O_RDWR, O_PATH };
	for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
		fd = syscall(SYS_openat, dirfd, "data", flags[i], 0);
		CHECK(fd >= 0 && close(fd) == 0);
	}
	const int missing[] = { O_RDONLY, O_WRONLY, O_RDWR };
	for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); i++) {
		CHECK(syscall(SYS_openat, dirfd, "missing", missing[i], 0) ==
			      -1 &&
		      errno == ENOENT);
	}
	detach(hook, 0);
	detach(hook, 1);
	CHECK(unlinkat(dirfd, "data", 0) == 0);
	CHECK(close(dirfd) == 0 && rmdir(dir) == 0);

	const char *classes[] = { "read", "write", "create", "other" };
	const uint64_t expected[][2] = {
		{ 2, 1 }, { 1, 2 }, { 1, 1 }, { 1, 0 }
	};
	printf("open-intent (success/failure):");
	for (size_t i = 0; i < sizeof(classes) / sizeof(classes[0]); i++) {
		uint64_t ok = read_word(0, 2 * i);
		uint64_t failed = read_word(0, 2 * i + 1);
		CHECK(ok == expected[i][0] && failed == expected[i][1]);
		printf(" %s=%" PRIu64 "/%" PRIu64, classes[i], ok, failed);
	}
	uint64_t unmatched = read_word(0, 8);
	CHECK(unmatched == 1);
	printf(" unmatched=%" PRIu64 "\n", unmatched);
	CHECK(rsm(RSM_UNLOAD, 0, 0) == 0);
}

#endif
