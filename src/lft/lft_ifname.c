/*
 *  lft_ifname.c
 *  Layer Four Traceroute
 *
 *  This file is part of LFT.
 *
 *  The LFT software provided in this Distribution is
 *  Copyright 2007 VOSTROM Holdings, Inc.
 *
 *  The full text of our legal notices is contained in the file called
 *  COPYING, included with this Distribution.
 *
 */

#if !defined(WIN32) && !defined(_WIN32)
#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#if !defined(linux) && !defined(__CYGWIN__)
#include <sys/sockio.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>

#include "lft_ifname.h"
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
#include "config/acconfig.win.h"
#else
#include "config/acconfig.h"
#endif

static int sock = -1;

u_long
lft_getifaddr (const char *ifname)
{
	struct ifreq ifr;
	struct sockaddr_in addr;

	/* Only do this once of course */
	if (sock < 0) {
		if ((sock = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
			perror ("socket");
			return -1;
		}
	}

	STRNCPY(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl");
		return -1;
	}

	if (ifr.ifr_addr.sa_family != AF_INET) {
		fprintf (stderr, "%s: Interface not configured with IPv4 address.\n", ifname);
		fflush (stderr);
		return -1;
	}

	memcpy(&addr, &ifr.ifr_addr, sizeof addr);

	return (addr.sin_addr.s_addr);
}

char *
lft_getifname (struct in_addr addr)
{
	struct ifconf		ifc;
	char buffer[2048];
	int i, skip;

	/* Only do this once of course */
	if (sock < 0) {
		if ((sock = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
			perror ("socket");
			return NULL;
		}
	}
	
	ifc.ifc_len = sizeof(buffer);
	ifc.ifc_buf = buffer;

	if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
		perror("ioctl");
		return NULL;
	}

	for (i = 0; i < ifc.ifc_len; i += skip) {
		struct ifreq ifr;
		struct in_addr thisaddr;

		memcpy(&ifr, ifc.ifc_buf + i, sizeof(struct ifreq));

		skip = sizeof(struct ifreq);
#ifdef HAVE_SOCKADDR_SA_LEN
		if (ifr.ifr_addr.sa_len > sizeof(struct sockaddr)) {
		  skip = ifr.ifr_addr.sa_len + IFNAMSIZ;
		}
#endif

		if (ifr.ifr_addr.sa_family != AF_INET) continue;

		thisaddr = ((const struct sockaddr_in *)(const void *)(&(ifr.ifr_addr)))->sin_addr;

		if (thisaddr.s_addr == addr.s_addr)
		  return strdup(ifr.ifr_name);
	}

	/* not found */
	return NULL;
}



#ifdef	LFT_IFADDR_TESTING
extern int
main (int argc, char *argv[])
{
	struct in_addr		in;
	char			*addr;

	if (argc > 1)
		addr = strdup (argv[1]);
	else
		addr = strdup ("eth0");

	in.s_addr = lft_getifaddr (addr);
	if (in.s_addr == -1) {
		fprintf (stderr, "%s: Error reading ifname\n", addr);
		fflush (stderr);
		free(addr);
		exit (-1);
	}

	fprintf (stdout, "%s: %s\n", addr,
		inet_ntoa (in));
	fflush (stdout);
	free (addr);
	exit (0);
}

#endif /*LFT_IFNAME_TESTING*/
#endif
