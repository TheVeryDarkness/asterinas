/* SPDX-License-Identifier: MPL-2.0 */

#ifndef SHOWCASE_PAGE_FAULTS_H
#define SHOWCASE_PAGE_FAULTS_H

#include <sys/mman.h>

static void check_page_faults(void)
{
	const uint64_t hook = find_hook(
		"aster_core::vm::vmar::vmar_impls::page_fault::Vmar::handle_page_fault");
	const long page_size = sysconf(_SC_PAGESIZE);
	const size_t pages = 32;
	CHECK(page_size > 0);
	size_t length = pages * (size_t)page_size;
	void *area = mmap(NULL, length, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(area != MAP_FAILED);
	volatile unsigned char *bytes = area;
	load("/test/rsm/page-faults.rsm.bin");
	uint64_t totals[2];
	for (size_t pass = 0; pass < 2; ++pass) {
		attach(hook, 1);
		for (size_t offset = 0; offset < length; offset += page_size)
			bytes[offset] = (unsigned char)(pass + 1);
		detach(hook, 1);
		totals[pass] = read_word(0, 0);
	}
	uint64_t warm = totals[1] - totals[0];
	uint64_t failed = read_word(0, 1);
	printf("page-faults: %zu pages, first write=%" PRIu64
	       " resolved, repeat=%" PRIu64 " resolved, rejected=%" PRIu64 "\n",
	       pages, totals[0], warm, failed);
	// Each anonymous page is materialized on first write. The hook is
	// system-wide, so incidental faults may also be observed in either window.
	CHECK(totals[0] >= pages && warm < pages && failed == 0);
	CHECK(rsm(RSM_UNLOAD, 0, 0) == 0);
	CHECK(munmap(area, length) == 0);
}

#endif
