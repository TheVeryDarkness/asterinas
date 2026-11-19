/* SPDX-License-Identifier: MPL-2.0 */

#ifndef SHOWCASE_BIND_OUTCOMES_H
#define SHOWCASE_BIND_OUTCOMES_H

#include <netinet/in.h>
#include <sys/socket.h>

static void exercise_bind_conflicts(int type, unsigned int retries)
{
	int owner = socket(AF_INET, type, 0);
	int contender = socket(AF_INET, type, 0);
	CHECK(owner >= 0 && contender >= 0);
	struct sockaddr_in endpoint = {
		.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};
	struct sockaddr *addr = (struct sockaddr *)&endpoint;
	socklen_t len = sizeof(endpoint);

	CHECK(bind(owner, addr, len) == 0);
	CHECK(getsockname(owner, addr, &len) == 0 && len == sizeof(endpoint) &&
	      endpoint.sin_port != 0);
	for (unsigned int i = 0; i < retries; i++)
		CHECK(bind(contender, addr, len) == -1 && errno == EADDRINUSE);

	// The same socket can still bind successfully if it requests a free port.
	endpoint.sin_port = 0;
	CHECK(bind(contender, addr, len) == 0);
	// An invalid descriptor fails before dispatch to either transport.
	CHECK(bind(-1, addr, len) == -1 && errno == EBADF);
	CHECK(close(contender) == 0 && close(owner) == 0);
}

static void check_bind_outcomes(void)
{
	uint64_t tcp = find_hook(
		"aster_core::net::socket::ip::stream::<StreamSocket as Socket>::bind");
	uint64_t udp = find_hook(
		"aster_core::net::socket::ip::datagram::<DatagramSocket as Socket>::bind");
	load("/test/rsm/bind-outcomes.rsm.bin");
	attach(tcp, 1);
	attach(udp, 1);
	exercise_bind_conflicts(SOCK_STREAM, 1);
	exercise_bind_conflicts(SOCK_DGRAM, 3);
	detach(udp, 1);
	detach(tcp, 1);

	uint64_t tcp_ok = read_word(tcp, 0), tcp_failed = read_word(tcp, 1);
	uint64_t udp_ok = read_word(udp, 0), udp_failed = read_word(udp, 1);
	printf("bind-outcomes: TCP ok=%" PRIu64 " failed=%" PRIu64
	       ", UDP ok=%" PRIu64 " failed=%" PRIu64 "\n",
	       tcp_ok, tcp_failed, udp_ok, udp_failed);
	CHECK(tcp_ok == 2 && tcp_failed == 1);
	CHECK(udp_ok == 2 && udp_failed == 3);
	CHECK(rsm(RSM_UNLOAD, 0, 0) == 0);
}

#endif
