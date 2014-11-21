/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

char copyright[] =
  "@(#) Copyright (c) 1989 The Regents of the University of California.\n"
  "All rights reserved.\n";
/*
 * From: @(#)ping.c	5.9 (Berkeley) 5/12/91
 */
char rcsid[] = "$Id: ping.c,v 1.22 1997/06/08 19:39:47 dholland Exp $";
char pkg[] = "netkit-base-0.10";

/*
 *			P I N G . C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *	Mike Muuss
 *	U. S. Army Ballistic Research Laboratory
 *	December, 1983
 *
 * Status -
 *	Public Domain.  Distribution Unlimited.
 * Bugs -
 *	More statistics could always be gathered.
 *	This program has to run SUID to ROOT to access the ICMP socket.
 */

#include <ec.h>
#ifdef HAVE_MAXMDB
#include "maxminddb.h"
#endif
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <lft/whois.h>

/*
 * Note: on some systems dropping root makes the process dumpable or
 * traceable. In that case if you enable dropping root and someone
 * traces ping, they get control of a raw socket and can start
 * spoofing whatever packets they like. SO BE CAREFUL.
 */
#ifdef __linux__
#define SAFE_TO_DROP_ROOT
#endif

#if defined(__GLIBC__) && (__GLIBC__ >= 2)
#define icmphdr			icmp
#define ICMP_DEST_UNREACH	ICMP_UNREACH
#define ICMP_NET_UNREACH	ICMP_UNREACH_NET
#define ICMP_HOST_UNREACH	ICMP_UNREACH_HOST
#define ICMP_PORT_UNREACH	ICMP_UNREACH_PORT
#define ICMP_PROT_UNREACH	ICMP_UNREACH_PROTOCOL
#define ICMP_FRAG_NEEDED	ICMP_UNREACH_NEEDFRAG
#define ICMP_SR_FAILED		ICMP_UNREACH_SRCFAIL
#define ICMP_NET_UNKNOWN	ICMP_UNREACH_NET_UNKNOWN
#define ICMP_HOST_UNKNOWN	ICMP_UNREACH_HOST_UNKNOWN
#define ICMP_HOST_ISOLATED	ICMP_UNREACH_ISOLATED
#define ICMP_NET_UNR_TOS	ICMP_UNREACH_TOSNET
#define ICMP_HOST_UNR_TOS	ICMP_UNREACH_TOSHOST
#define ICMP_SOURCE_QUENCH	ICMP_SOURCEQUENCH
#define ICMP_REDIR_NET		ICMP_REDIRECT_NET
#define ICMP_REDIR_HOST		ICMP_REDIRECT_HOST
#define ICMP_REDIR_NETTOS	ICMP_REDIRECT_TOSNET
#define ICMP_REDIR_HOSTTOS	ICMP_REDIRECT_TOSHOST
#define ICMP_TIME_EXCEEDED	ICMP_TIMXCEED
#define ICMP_EXC_TTL		ICMP_TIMXCEED_INTRANS
#define ICMP_EXC_FRAGTIME	ICMP_TIMXCEED_REASS
#define	ICMP_PARAMETERPROB	ICMP_PARAMPROB
#define ICMP_TIMESTAMP		ICMP_TSTAMP
#define ICMP_TIMESTAMPREPLY	ICMP_TSTAMPREPLY
#define ICMP_INFO_REQUEST	ICMP_IREQ
#define ICMP_INFO_REPLY		ICMP_IREQREPLY
#else
#define ICMP_MINLEN	28
#define inet_ntoa(x) inet_ntoa(*((struct in_addr *)&(x)))
#endif


#define	DEFDATALEN	(56 - 8)	/* default data length */
#define	MAXIPLEN	60
#define	MAXICMPLEN	76
#define	MAXPACKET	(65536 - 60 - 8)/* max packet size */
#define	MAXWAIT		10		/* max seconds to wait for response */
#define	NROUTES		9		/* number of record route slots */

#define	A(bit)		rcvd_tbl[(bit)>>3]	/* identify byte in array */
#define	B(bit)		(1 << ((bit) & 0x07))	/* identify bit in byte */
#define	SET(bit)	(A(bit) |= B(bit))
#define	CLR(bit)	(A(bit) &= (~B(bit)))
#define	TST(bit)	(A(bit) & B(bit))

/* various options */
int options;
#define	F_FLOOD		0x001
#define	F_INTERVAL	0x002
#define	F_NUMERIC	0x004
#define	F_PINGFILLED	0x008
#define	F_QUIET		0x010
#define	F_RROUTE	0x020
#define	F_SO_DEBUG	0x040
#define	F_SO_DONTROUTE	0x080
#define	F_VERBOSE	0x100

/* multicast options */
int moptions;
#define MULTICAST_NOLOOP	0x001
#define MULTICAST_TTL		0x002
#define MULTICAST_IF		0x004

/*
 * MAX_DUP_CHK is the number of bits in received table, i.e. the maximum
 * number of received sequence numbers we can keep track of.  Change 128
 * to 8192 for complete accuracy...
 */
#define	MAX_DUP_CHK	(8 * 128)
int mx_dup_ck = MAX_DUP_CHK;
char rcvd_tbl[MAX_DUP_CHK / 8];

struct sockaddr whereto;	/* who to ping */
int datalen = DEFDATALEN;
int s;				/* socket file descriptor */
u_char outpack[MAXPACKET];
char BSPACE = '\b';		/* characters written for flood */
char DOT = '.';
static char *hostname;
static int ident;		/* process id to identify our packets */

/* output */
#define UI stdout
#define LOG stderr

/* MMDB */
#ifdef HAVE_MAXMDB
MMDB_s *mmdb = NULL;
static void open_or_die(const char *fname);
static MMDB_lookup_result_s lookup_or_die(MMDB_s *mmdb, const char *ipstr);
static int lookup_and_print(MMDB_s *mmdb, const char *ip_address,
                           const char **lookup_path,
                           int lookup_path_length,
                           char *desc,
                           int len);
#endif

/* counters */
static long npackets;		/* max packets to transmit */
static long nreceived;		/* # of packets we got back */
static long nrepeats;		/* number of duplicates */
static long ntransmitted;	/* sequence # for outbound packets = #sent */
static int interval = 1;	/* interval between packets */

/* timing */
static int timing;		/* flag to do timing */
static long tmin = LONG_MAX;	/* minimum round trip time */
static long tmax = 0;		/* maximum round trip time */
static u_long tsum;		/* sum of all times, for doing average */

/* protos */
static char *pr_addr(u_long);
static int in_cksum(u_short *addr, int len);
static int pinger(void);
static void fill(void *bp, char *patp);
static void usage(void);
static void pr_pack(char *buf, int cc, struct sockaddr_in *from);
static void tvsub(struct timeval *out, struct timeval *in);
static void pr_icmph(struct icmphdr *icp);
static void pr_retip(struct iphdr *ip);
static int progress(char *title, int value, int max);

void
ping_init(void)
{
	struct protoent *proto;
	int hold;
	/*
	 * Pull this stuff up front so we can drop root if desired.
	 */
	if (!(proto = getprotobyname("icmp"))) {
		(void)fprintf(LOG, "ping: unknown protocol icmp.\n");
		exit(2);
	}
	if ((s = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) {
		if (errno==EPERM) {
			fprintf(LOG, "ping: ping must run as root\n");
		}
		else perror("ping: socket");
		exit(2);
	}


	ident = getpid() & 0xFFFF;
	hold = 1;

	/* this is necessary for broadcast pings to work */
	setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&hold, sizeof(hold));

	/*
	 * When pinging the broadcast address, you can get a lot of answers.
	 * Doing something so evil is useful if you are trying to stress the
	 * ethernet, or just want to fill the arp cache to get some stuff for
	 * /etc/ethers.
	 */
	hold = 48 * 1024;
	(void)setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&hold,
	    sizeof(hold));

#ifdef HAVE_MAXMDB
	if ( GBL_OPTIONS->geoip2_file )
       open_or_die(GBL_OPTIONS->geoip2_file);
#endif
}

int
do_whois( char * target, char *desc, size_t len )
{
	char *orgname;
	char *netname;
	int   cnt, ret, err;
	char *cp = desc;
	whois_session_params * wsess;
	ret = 0;
	wsess = w_init();
	if ( (err = w_lookup_all_pwhois( wsess, target )) < 0 ) {
		return err;
	}
    if ( wsess->consolidated_asorgname ) {
    	cnt = snprintf(cp, len, ", %s", wsess->consolidated_asorgname );
    	if ( cnt > len )
    		cnt = len;
        len -= cnt;
        cp += cnt;
        ret += cnt;
    }
    if ( wsess->consolidated_orgname ) {
    	cnt = snprintf(cp, len, ", %s", wsess->consolidated_orgname );
    	if ( cnt > len )
    		cnt = len;
        len -= cnt;
        cp += cnt;
        ret += cnt;
    }
    if ( wsess->consolidated_city ) {
    	cnt = snprintf(cp, len, ", %s", wsess->consolidated_city );
    	if ( cnt > len )
    		cnt = len;
        len -= cnt;
        cp += cnt;
        ret += cnt;
    }
    if ( wsess->consolidated_country ) {
    	cnt = snprintf(cp, len, ", %s", wsess->consolidated_country );
    	if ( cnt > len )
    		cnt = len;
        len -= cnt;
        cp += cnt;
        ret += cnt;
    }
	return ret;
}

#ifdef HAVE_MAXMDB
int
do_geoip( char * target, char *desc, size_t len )
{
	if ( !mmdb )
		return 0;

    const char *country_lookup_path[] = {"country", "names", "en", NULL};
    const char *city_lookup_path[] = {"city", "names", "en", NULL};
    const char *sub_lookup_path[] = {"subdivisions", "names", "names", "en", NULL};
    char *ip_address = target;
    int lookup_path_length = 1;
    int cnt = 0;
    int ret = 0;
    char *buf = malloc(len);
    char *cp = desc;

    cnt = lookup_and_print(mmdb, ip_address, country_lookup_path,
                              lookup_path_length, buf, len);
    if ( cnt ) {
    	cnt = snprintf(cp, len, ", %s", buf );
    	if ( cnt > len )
    		cnt = len;
        len -= cnt;
        cp += cnt;
        ret += cnt;
    }

    cnt = lookup_and_print(mmdb, ip_address, sub_lookup_path,
                          lookup_path_length, buf, len);
    if ( cnt ) {
    	cnt = snprintf(cp, len, ", %s", buf );
    	if ( cnt > len )
    		cnt = len;
        len -= cnt;
        cp += cnt;
        ret += cnt;
    }
    cnt = lookup_and_print(mmdb, ip_address, city_lookup_path,
                              lookup_path_length, buf, len);
    if ( cnt ) {
    	cnt = snprintf(cp, len, ", %s", buf );
    	if ( cnt > len )
    		cnt = len;
        len -= cnt;
        cp += cnt;
        ret += cnt;
    }
    free(buf);

    return ret;
}
#endif

int
do_ping( char * target, char *desc, size_t len, int mode )
{
	int preload, fdmask, packlen, ret;
	u_char *packet;
	struct timeval timeout;
	struct sockaddr_in *to;
	struct hostent *hp;
	char hnamebuf[MAXHOSTNAMELEN];

	npackets = GBL_OPTIONS->ping;
	interval = GBL_OPTIONS->interval;
	preload = 0;
	ret = 0;

	ntransmitted = 0;
	nreceived = 0;
	nrepeats = 0;
	tmin = LONG_MAX;
	tmax = 0;
	tsum = 0;

	memset(&whereto, 0, sizeof(struct sockaddr));
	to = (struct sockaddr_in *)&whereto;
	to->sin_family = AF_INET;
	if (inet_aton(target, &to->sin_addr)) {
		hostname = target;
	}
	else {
		hp = gethostbyname(target);
		if (!hp) {
			(void)fprintf(LOG,
			    "ping: unknown host %s\n", target);
			exit(2);
		}
		to->sin_family = hp->h_addrtype;
		if (hp->h_length > (int)sizeof(to->sin_addr)) {
			hp->h_length = sizeof(to->sin_addr);
		}
		memcpy(&to->sin_addr, hp->h_addr, hp->h_length);
		(void)strncpy(hnamebuf, hp->h_name, sizeof(hnamebuf) - 1);
		hostname = hnamebuf;
	}

	if (datalen >= (int)sizeof(struct timeval)) /* can we time transfer */
		timing = 1;
	packlen = datalen + MAXIPLEN + MAXICMPLEN;
	packet = malloc((u_int)packlen);
	if (!packet) {
		(void)fprintf(LOG, "ping: out of memory.\n");
		exit(2);
	}

/*	if (to->sin_family == AF_INET)
		(void)fprintf(LOG, "PING %s (%s): %d data bytes\n", hostname,
		    inet_ntoa(*(struct in_addr *)&to->sin_addr.s_addr),
		    datalen);
	else
		(void)fprintf(LOG, "PING %s: %d data bytes\n", hostname, datalen); */

	while (preload--) {		/* fire off them quickies */
		ret = pinger();
		if ( ret < 0 ) {
			ret = snprintf(desc, len, "PING %s sendto error", mode ? "DST" : "SRC");
			return ret;
		}
	}

    //if ((options & F_FLOOD) == 0)
    //        catcher(0);             /* start things going */

	for (;;) {
		struct sockaddr_in from;
		register int cc;
		size_t fromlen;

		progress(target, ntransmitted, npackets);

		if (npackets && ntransmitted >= npackets)
			break;

		//if (options & F_FLOOD) {
		ret = pinger();
		if ( ret < 0 ) {
			ret = snprintf(desc, len, "PING %s sendto error", mode ? "DST" : "SRC");
			break;
		}
		timeout.tv_sec = 0;
		timeout.tv_usec = interval;
		fdmask = 1 << s;
		if (select(s + 1, (fd_set *)&fdmask, (fd_set *)NULL,
				(fd_set *)NULL, &timeout) < 1) {
			continue;
		}
		//}

		fromlen = sizeof(from);
		if ((cc = recvfrom(s, (char *)packet, packlen, 0,
				(struct sockaddr *)&from, &fromlen)) < 0) {
			if (errno == EINTR)
				continue;
			perror("ping: recvfrom");
			continue;
		}
		pr_pack((char *)packet, cc, &from);
	}

	if (timing)
		if ( nreceived ) {
			ret = snprintf(desc, len, "PING %s min/avg/max: %ld.%ld/%lu.%ld/%ld.%ld ms loss: %d%%",
					mode ? "DST" : "SRC",
							tmin/10, tmin%10,
							(tsum / (nreceived + nrepeats))/10,
							(tsum / (nreceived + nrepeats))%10,
							tmax/10, tmax%10,
							(int) (((ntransmitted - nreceived) * 100) /
									ntransmitted));
		} else {
		   ret = snprintf(desc, len, "PING %s No Reply", mode ? "DST" : "SRC");
	    }
	free(packet);
	fputc('\r', UI);
	return ret;
}

#if !defined(__GLIBC__) || (__GLIBC__ < 2)
#define icmp_type type
#define icmp_code code
#define icmp_cksum checksum
#define icmp_id un.echo.id
#define icmp_seq un.echo.sequence
#define icmp_gwaddr un.gateway
#endif /* __GLIBC__ */

#define ip_hl ihl
#define ip_v version
#define ip_tos tos
#define ip_len tot_len
#define ip_id id
#define ip_off frag_off
#define ip_ttl ttl
#define ip_p protocol
#define ip_sum check
#define ip_src saddr
#define ip_dst daddr

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
static int
pinger(void)
{
	register struct icmphdr *icp;
	register int cc;
	int i;

	icp = (struct icmphdr *)outpack;
	icp->icmp_type = ICMP_ECHO;
	icp->icmp_code = 0;
	icp->icmp_cksum = 0;
	icp->icmp_seq = ntransmitted++;
	icp->icmp_id = ident;			/* ID */

	CLR(icp->icmp_seq % mx_dup_ck);

	if (timing)
		(void)gettimeofday((struct timeval *)&outpack[8],
		    (struct timezone *)NULL);

	cc = datalen + 8;			/* skips ICMP portion */

	/* compute ICMP checksum here */
	icp->icmp_cksum = in_cksum((u_short *)icp, cc);

	i = sendto(s, (char *)outpack, cc, 0, &whereto,
	    sizeof(struct sockaddr));

	if (i < 0 || i != cc)  {
		if (i < 0)
			perror("ping: sendto");
		(void)fprintf(LOG, "ping: wrote %s %d chars, ret=%d\n",
		    hostname, cc, i);
	}
	if (!(options & F_QUIET) && options & F_FLOOD)
		(void)write(STDOUT_FILENO, &DOT, 1);
	return i;
}

/*
 * pr_pack --
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
void
pr_pack(char *buf, int cc, struct sockaddr_in *from)
{
	register struct icmphdr *icp;
	register int i;
	register u_char *cp,*dp;
/*#if 0*/
	register u_long l;
	register int j;
	static int old_rrlen;
	static char old_rr[MAX_IPOPTLEN];
/*#endif*/
	struct iphdr *ip;
	struct timeval tv, *tp;
	long triptime = 0;
	int hlen, dupflag;

	(void)gettimeofday(&tv, (struct timezone *)NULL);

	/* Check the IP header */
	ip = (struct iphdr *)buf;
	hlen = ip->ip_hl << 2;
	if (cc < datalen + ICMP_MINLEN) {
		if (options & F_VERBOSE)
			(void)fprintf(LOG,
			  "ping: packet too short (%d bytes < %d bytes) from %s\n", cc, datalen + ICMP_MINLEN,
			  inet_ntoa(*(struct in_addr *)&from->sin_addr.s_addr));
		return;
	}

	/* Now the ICMP part */
	cc -= hlen;
	icp = (struct icmphdr *)(buf + hlen);
	if (icp->icmp_type == ICMP_ECHOREPLY) {
		if (icp->icmp_id != ident) {
			return;			/* 'Twas not our ECHO */
		}
		++nreceived;
		if (timing) {
#ifndef icmp_data
			tp = (struct timeval *)(icp + 1);
#else
			tp = (struct timeval *)icp->icmp_data;
#endif
			tvsub(&tv, tp);
			triptime = tv.tv_sec * 10000 + (tv.tv_usec / 100);
			tsum += triptime;
			if (triptime < tmin)
				tmin = triptime;
			if (triptime > tmax)
				tmax = triptime;
		}

		if (TST(icp->icmp_seq % mx_dup_ck)) {
			++nrepeats;
			--nreceived;
			dupflag = 1;
		} else {
			SET(icp->icmp_seq % mx_dup_ck);
			dupflag = 0;
		}

		if (options & F_FLOOD)
			(void)write(STDOUT_FILENO, &BSPACE, 1);
		else {
			if (options & F_VERBOSE) {
				(void)fprintf(LOG, "%d bytes from %s: icmp_seq=%u", cc,
						inet_ntoa(*(struct in_addr *)&from->sin_addr.s_addr),
						icp->icmp_seq);
				(void)fprintf(LOG, " ttl=%d", ip->ip_ttl);
				if (timing)
					(void)fprintf(LOG, " time=%ld.%ld ms", triptime/10,
							triptime%10);
				if (dupflag)
					(void)fprintf(LOG, " (DUP!)");
			}
			/* check the data */
#ifndef icmp_data
			cp = ((u_char*)(icp + 1));
#else
			cp = (u_char*)icp->icmp_data;
#endif
			dp = &outpack[8];
			for (i = 0; i < datalen; ++i, cp++, dp++) {
				if (*cp != *dp) {
	(void)fprintf(LOG, "\nERROR: wrong data byte #%d should be 0x%x but was 0x%x",
	    i, *dp, *cp);
#ifndef icmp_data
			cp = ((u_char*)(icp + 1));
#else
			cp = (u_char*)icp->icmp_data;
#endif
			dp = &outpack[8];
					(void)fprintf(LOG, "\nreceived:\n\t");
					for (i = 8; i < datalen; ++i, cp++) {
						if ((i % 32) == 8)
							(void)fprintf(LOG, "\n\t");
						(void)fprintf(LOG, "%x,", *cp);
					}
                    (void)fprintf(LOG, "\nsent:\n\t");

					for (i = 0; i < datalen; ++i, dp++) {
						if ((i % 32) == 8)
							(void)fprintf(LOG, "\n\t");
						(void)fprintf(LOG, "%x,", *dp);
					}
					(void)fprintf(LOG, "\n");
					break;
				}
			}
		}
	} else {
		/* We've got something other than an ECHOREPLY */
		if (!(options & F_VERBOSE))
			return;
		(void)fprintf(LOG, "%d bytes from %s: ", cc,
		    pr_addr(from->sin_addr.s_addr));
		pr_icmph(icp);
	}

/*#if 0*/
	/* Display any IP options */
	cp = (u_char *)buf + sizeof(struct iphdr);

	for (; hlen > (int)sizeof(struct iphdr); --hlen, ++cp)
		switch (*cp) {
		case IPOPT_EOL:
			hlen = 0;
			break;
		case IPOPT_LSRR:
			(void)fprintf(LOG, "\nLSRR: ");
			hlen -= 2;
			j = *++cp;
			++cp;
			if (j > IPOPT_MINOFF)
				for (;;) {
					l = *++cp;
					l = (l<<8) + *++cp;
					l = (l<<8) + *++cp;
					l = (l<<8) + *++cp;
					if (l == 0)
						(void)fprintf(LOG, "\t0.0.0.0");
				else
					(void)fprintf(LOG, "\t%s", pr_addr(ntohl(l)));
				hlen -= 4;
				j -= 4;
				if (j <= IPOPT_MINOFF)
					break;
				(void)fputc('\n', LOG);
			}
			break;
		case IPOPT_RR:
			j = *++cp;		/* get length */
			i = *++cp;		/* and pointer */
			hlen -= 2;
			if (i > j)
				i = j;
			i -= IPOPT_MINOFF;
			if (i <= 0)
				continue;
			if (i == old_rrlen
			    && cp == (u_char *)buf + sizeof(struct iphdr) + 2
			    && !memcmp((char *)cp, old_rr, i)
			    && !(options & F_FLOOD)) {
				(void)fprintf(LOG, "\t(same route)");
				i = ((i + 3) / 4) * 4;
				hlen -= i;
				cp += i;
				break;
			}
			old_rrlen = i;
			memcpy(old_rr, cp, i);
			(void)fprintf(LOG, "\nRR: ");
			for (;;) {
				l = *++cp;
				l = (l<<8) + *++cp;
				l = (l<<8) + *++cp;
				l = (l<<8) + *++cp;
				if (l == 0)
					(void)fprintf(LOG, "\t0.0.0.0");
				else
					(void)fprintf(LOG, "\t%s", pr_addr(ntohl(l)));
				hlen -= 4;
				i -= 4;
				if (i <= 0)
					break;
				(void)fputc('\n', LOG);
			}
			break;
		case IPOPT_NOP:
			(void)fprintf(LOG, "\nNOP");
			break;
		default:
			(void)fprintf(LOG, "\nunknown option %x", *cp);
			break;
		}
/*#endif*/
	if (!(options & F_FLOOD) && (options & F_VERBOSE)) {
		(void)fputc('\n', LOG);
		(void)fflush(LOG);
	}
}

/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
static int
in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

/*
 * tvsub --
 *	Subtract 2 timeval structs:  out = out - in.  Out is assumed to
 * be >= in.
 */
static void
tvsub(register struct timeval *out, register struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

/*
 * pr_icmph --
 *	Print a descriptive string about an ICMP header.
 */
static void
pr_icmph(struct icmphdr *icp)
{
	switch(icp->icmp_type) {
	case ICMP_ECHOREPLY:
		(void)fprintf(LOG, "Echo Reply\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_DEST_UNREACH:
		switch(icp->icmp_code) {
		case ICMP_NET_UNREACH:
			(void)fprintf(LOG, "Destination Net Unreachable\n");
			break;
		case ICMP_HOST_UNREACH:
			(void)fprintf(LOG, "Destination Host Unreachable\n");
			break;
		case ICMP_PROT_UNREACH:
			(void)fprintf(LOG, "Destination Protocol Unreachable\n");
			break;
		case ICMP_PORT_UNREACH:
			(void)fprintf(LOG, "Destination Port Unreachable\n");
			break;
		case ICMP_FRAG_NEEDED:
			(void)fprintf(LOG, "frag needed and DF set\n");
			break;
		case ICMP_SR_FAILED:
			(void)fprintf(LOG, "Source Route Failed\n");
			break;
		case ICMP_NET_UNKNOWN:
			(void)fprintf(LOG, "Network Unknown\n");
			break;
		case ICMP_HOST_UNKNOWN:
			(void)fprintf(LOG, "Host Unknown\n");
			break;
		case ICMP_HOST_ISOLATED:
			(void)fprintf(LOG, "Host Isolated\n");
			break;
		case ICMP_NET_UNR_TOS:
			printf("Destination Network Unreachable At This TOS\n");
			break;
		case ICMP_HOST_UNR_TOS:
			printf("Destination Host Unreachable At This TOS\n");
			break;
#ifdef ICMP_PKT_FILTERED
		case ICMP_PKT_FILTERED:
			(void)fprintf(LOG, "Packet Filtered\n");
			break;
#endif
#ifdef ICMP_PREC_VIOLATION
		case ICMP_PREC_VIOLATION:
			(void)fprintf(LOG, "Precedence Violation\n");
			break;
#endif
#ifdef ICMP_PREC_CUTOFF
		case ICMP_PREC_CUTOFF:
			(void)fprintf(LOG, "Precedence Cutoff\n");
			break;
#endif
		default:
			(void)fprintf(LOG, "Dest Unreachable, Unknown Code: %d\n",
			    icp->icmp_code);
			break;
		}
		/* Print returned IP header information */
#ifndef icmp_data
		pr_retip((struct iphdr *)(icp + 1));
#else
		pr_retip((struct iphdr *)icp->icmp_data);
#endif
		break;
	case ICMP_SOURCE_QUENCH:
		(void)fprintf(LOG, "Source Quench\n");
#ifndef icmp_data
		pr_retip((struct iphdr *)(icp + 1));
#else
		pr_retip((struct iphdr *)icp->icmp_data);
#endif
		break;
	case ICMP_REDIRECT:
		switch(icp->icmp_code) {
		case ICMP_REDIR_NET:
			(void)fprintf(LOG, "Redirect Network");
			break;
		case ICMP_REDIR_HOST:
			(void)fprintf(LOG, "Redirect Host");
			break;
		case ICMP_REDIR_NETTOS:
			(void)fprintf(LOG, "Redirect Type of Service and Network");
			break;
		case ICMP_REDIR_HOSTTOS:
			(void)fprintf(LOG, "Redirect Type of Service and Host");
			break;
		default:
			(void)fprintf(LOG, "Redirect, Bad Code: %d", icp->icmp_code);
			break;
		}
		(void)fprintf(LOG, "(New addr: %s)\n",
			     inet_ntoa(icp->icmp_gwaddr));
#ifndef icmp_data
		pr_retip((struct iphdr *)(icp + 1));
#else
		pr_retip((struct iphdr *)icp->icmp_data);
#endif
		break;
	case ICMP_ECHO:
		(void)fprintf(LOG, "Echo Request\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_TIME_EXCEEDED:
		switch(icp->icmp_code) {
		case ICMP_EXC_TTL:
			(void)fprintf(LOG, "Time to live exceeded\n");
			break;
		case ICMP_EXC_FRAGTIME:
			(void)fprintf(LOG, "Frag reassembly time exceeded\n");
			break;
		default:
			(void)fprintf(LOG, "Time exceeded, Bad Code: %d\n",
			    icp->icmp_code);
			break;
		}
#ifndef icmp_data
		pr_retip((struct iphdr *)(icp + 1));
#else
		pr_retip((struct iphdr *)icp->icmp_data);
#endif
		break;
	case ICMP_PARAMETERPROB:
		(void)fprintf(LOG, "Parameter problem: IP address = %s\n",
			inet_ntoa (icp->icmp_gwaddr));
#ifndef icmp_data
		pr_retip((struct iphdr *)(icp + 1));
#else
		pr_retip((struct iphdr *)icp->icmp_data);
#endif
		break;
	case ICMP_TIMESTAMP:
		(void)fprintf(LOG, "Timestamp\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_TIMESTAMPREPLY:
		(void)fprintf(LOG, "Timestamp Reply\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_INFO_REQUEST:
		(void)fprintf(LOG, "Information Request\n");
		/* XXX ID + Seq */
		break;
	case ICMP_INFO_REPLY:
		(void)fprintf(LOG, "Information Reply\n");
		/* XXX ID + Seq */
		break;
#ifdef ICMP_MASKREQ
	case ICMP_MASKREQ:
		(void)fprintf(LOG, "Address Mask Request\n");
		break;
#endif
#ifdef ICMP_MASKREPLY
	case ICMP_MASKREPLY:
		(void)fprintf(LOG, "Address Mask Reply\n");
		break;
#endif
	default:
		(void)fprintf(LOG, "Bad ICMP type: %d\n", icp->icmp_type);
	}
}

/*
 * pr_iph --
 *	Print an IP header with options.
 */
static void
pr_iph(struct iphdr *ip)
{
	int hlen;
	u_char *cp;

	hlen = ip->ip_hl << 2;
	cp = (u_char *)ip + 20;		/* point to options */

	(void)fprintf(LOG, "Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n");
	(void)fprintf(LOG, " %1x  %1x  %02x %04x %04x",
	    ip->ip_v, ip->ip_hl, ip->ip_tos, ip->ip_len, ip->ip_id);
	(void)fprintf(LOG, "   %1x %04x", ((ip->ip_off) & 0xe000) >> 13,
	    (ip->ip_off) & 0x1fff);
	(void)fprintf(LOG, "  %02x  %02x %04x", ip->ip_ttl, ip->ip_p, ip->ip_sum);
	(void)fprintf(LOG, " %s ", inet_ntoa(*((struct in_addr *) &ip->ip_src)));
	(void)fprintf(LOG, " %s ", inet_ntoa(*((struct in_addr *) &ip->ip_dst)));
	/* dump and option bytes */
	while (hlen-- > 20) {
		(void)fprintf(LOG, "%02x", *cp++);
	}
	(void)fputc('\n', LOG);
}

/*
 * pr_addr --
 *	Return an ascii host address as a dotted quad and optionally with
 * a hostname.
 */
static char *
pr_addr(u_long l)
{
	struct hostent *hp;
	static char buf[256];

	if ((options & F_NUMERIC) ||
	    !(hp = gethostbyaddr((char *)&l, 4, AF_INET)))
		(void)snprintf(buf, sizeof(buf), "%s", 
			       inet_ntoa(*(struct in_addr *)&l));
	else
		(void)snprintf(buf, sizeof(buf), "%s (%s)", hp->h_name,
		    inet_ntoa(*(struct in_addr *)&l));
	return(buf);
}

/*
 * pr_retip --
 *	Dump some info on a returned (via ICMP) IP packet.
 */
static void
pr_retip(struct iphdr *ip)
{
	int hlen;
	u_char *cp;

	pr_iph(ip);
	hlen = ip->ip_hl << 2;
	cp = (u_char *)ip + hlen;

	if (ip->ip_p == 6)
		(void)fprintf(LOG, "TCP: from port %u, to port %u (decimal)\n",
		    (*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));
	else if (ip->ip_p == 17)
		(void)fprintf(LOG, "UDP: from port %u, to port %u (decimal)\n",
			(*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));
}

static void
fill(void *bp1, char *patp)
{
	register int ii, jj, kk;
	int pat[16];
	char *cp, *bp = (char *)bp1;

	for (cp = patp; *cp; cp++)
		if (!isxdigit(*cp)) {
			(void)fprintf(UI,
			    "ping: patterns must be specified as hex digits.\n");
			exit(2);
		}
	ii = sscanf(patp,
	    "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
	    &pat[0], &pat[1], &pat[2], &pat[3], &pat[4], &pat[5], &pat[6],
	    &pat[7], &pat[8], &pat[9], &pat[10], &pat[11], &pat[12],
	    &pat[13], &pat[14], &pat[15]);

	if (ii > 0)
		for (kk = 0; kk <= MAXPACKET - (8 + ii); kk += ii)
			for (jj = 0; jj < ii; ++jj)
				bp[jj + kk] = pat[jj];
	if (!(options & F_QUIET)) {
		(void)fprintf(LOG, "PATTERN: 0x");
		for (jj = 0; jj < ii; ++jj)
			(void)fprintf(LOG, "%02x", bp[jj] & 0xFF);
		(void)fprintf(LOG, "\n");
	}
}

void
usage(void)
{
	(void)fprintf(UI,
	    "usage: ping [-LRdfnqrv] [-c count] [-i wait] [-l preload]\n\t[-p pattern] [-s packetsize] [-t ttl] [-I interface address] host\n");
	exit(2);
}

/*
 * implement the progress bar
 */
static int progress(char *title, int value, int max)
{
   float percent;
   int i;

   /* calculate the percent */
   percent = (float)(value)*100/(max);

   /*
    * we use LOG to avoid scrambling of
    * logfile generated by: ./ettercap -T > logfile
    */

   switch(value % 4) {
      case 0:
         fprintf(UI, "\r| |");
      break;
      case 1:
         fprintf(UI, "\r/ |");
      break;
      case 2:
         fprintf(UI, "\r- |");
      break;
      case 3:
         fprintf(UI, "\r\\ |");
      break;
   }

   /* fill the bar */
   for (i=0; i < percent/2; i++)
      fprintf(UI, "=");

   fprintf(UI, ">");

   /* fill the empty part of the bar */
   for(; i < 50; i++)
      fprintf(UI, " ");

   fprintf(UI, "| %6.2f %%", percent );

   fflush(UI);

   if (value == max) {
      fprintf(UI, "\r* |==================================================>| 100.00 %%");
      fflush(UI);
      return UI_PROGRESS_FINISHED;
   }

   return UI_PROGRESS_UPDATED;
}

#ifdef HAVE_MAXMDB
static void open_or_die(const char *fname)
{
	mmdb = malloc(sizeof(MMDB_s),1);
    int status = MMDB_open(fname, MMDB_MODE_MMAP, mmdb);

    if (MMDB_SUCCESS != status) {
        fprintf(UI, "\n  Can't open %s - %s\n", fname,
                MMDB_strerror(status));

        if (MMDB_IO_ERROR == status) {
            fprintf(UI, "    IO error: %s\n", strerror(errno));
        }

        fprintf(UI, "\n");

        exit(2);
    }

}

static MMDB_lookup_result_s lookup_or_die(MMDB_s *mmdb, const char *ipstr)
{
    int gai_error, mmdb_error;
    MMDB_lookup_result_s result =
        MMDB_lookup_string(mmdb, ipstr, &gai_error, &mmdb_error);

    if (0 != gai_error) {
        fprintf(LOG,
                "\n  Error from call to getaddrinfo for %s - %s\n\n",
                ipstr, gai_strerror(gai_error));
        exit(3);
    }

    if (MMDB_SUCCESS != mmdb_error) {
        fprintf(LOG, "\n  Got an error from the maxminddb library: %s\n\n",
                MMDB_strerror(mmdb_error));
        exit(4);
    }

    return result;
}

static int lookup_and_print(MMDB_s *mmdb, const char *ip_address,
                           const char **lookup_path,
                           int lookup_path_length,
                           char *desc,
                           int len)
{

	int ret = 0;
	char *cp = desc;
    int datalen = 0;
    char *datastr = NULL;
    MMDB_lookup_result_s result = lookup_or_die(mmdb, ip_address);
    MMDB_entry_data_list_s *entry_data_list = NULL;

    if (result.found_entry) {
        int status;
        if (lookup_path_length) {
            MMDB_entry_data_s entry_data;
            status = MMDB_aget_value(&result.entry, &entry_data,
                                     lookup_path);
            if (MMDB_SUCCESS == status) {
                if (entry_data.offset) {
                    MMDB_entry_s entry =
                    { .mmdb = mmdb, .offset = entry_data.offset };
                    status = MMDB_get_entry_data_list(&entry,
                                                      &entry_data_list);
                } else {
                    ret = snprintf(cp, len, "GeoIP-failed");
                    if ( ret > len ) ret = len;
                }
            }
        } else {
            status = MMDB_get_entry_data_list(&result.entry,
                                              &entry_data_list);
        }

        if (MMDB_SUCCESS != status) {
            goto end;
        }

        if (NULL != entry_data_list) {
        	switch (entry_data_list->entry_data.type) {
            case MMDB_DATA_TYPE_UTF8_STRING:
                datalen = entry_data_list->entry_data.data_size;
                datastr = (char *)entry_data_list->entry_data.utf8_string;
                if ((datalen + 1) > len)
                {
                	ret = snprintf(cp, len, "GeoIP-overflow");
                	if ( ret > len ) ret = len;
                	goto end;
                } else {
                    memcpy(cp, datastr, datalen);
                    cp[datalen] = '\0';
                    ret = datalen + 1;
                }

            break;
        	default:
        		ret = snprintf(cp, len, "GeoIP-unknown");
        		if ( ret > len ) ret = len;
            break;
            }
        }
    }
 end:
    MMDB_free_entry_data_list(entry_data_list);

    return ret;
}
#endif


