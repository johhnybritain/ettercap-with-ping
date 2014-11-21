/*
 *  lft_types.h
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
#ifndef LFT_TYPES_H
#define LFT_TYPES_H

#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
#include "config/acconfig.win.h"
#else
#include "config/acconfig.h"
#endif
#include <assert.h>
#ifndef __FAVOR_BSD
# define __FAVOR_BSD	1
#endif
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
#define __USE_W32_SOCKETS
#include <Winsock2.h>
#include <windows.h>
#include <Ws2tcpip.h>
#include <sys/types.h>
#define LITTLE_ENDIAN 1
#define BYTE_ORDER 1
typedef signed long n_long;
typedef signed short n_short;
typedef signed long n_time;
#include <stdio.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#ifdef __CYGWIN__
# include <getopt.h>
#else
# include "include/win32/wingetopt.h"
# if defined(WIN32) || defined(_WIN32)
#  define SIZEOF_CHAR     1
#  define SIZEOF_SHORT    2
#  define SIZEOF_LONG     4
#  define SIZEOF_LONG_LONG    8
#  include "include/libpcap/bittypes.h"
#  include "include/libpcap/Gnuc.h"
#  define bzero(buf,cnt)    memset(buf,'\0',cnt);
# endif
#endif
#include "include/net/if_arp.h"
#include "include/netinet/if_ether.h"
#include "include/netinet/ip.h"
#include "include/netinet/ip_icmp.h"
#include "include/netinet/tcp.h"
#include "include/netinet/udp.h"
#else
#include <stdarg.h>
#include <sys/types.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <stdio.h>
#include <ctype.h>
#include <math.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

#ifdef BSD
#include <machine/limits.h>
#endif

#ifdef BSD_IP_STACK
#include <sys/ioctl.h>
#include <net/bpf.h>
#if !defined(DARWIN) && !defined(NETBSD)
#define HAVE_SNPRINTF
#define HAVE_VSNPRINTF
#include <pcap-int.h>
#endif
#endif

#include <pcap.h>

#ifdef sun
#include <limits.h>
#include <strings.h>
#endif

#endif

#include "lft_ifname.h"
#include "lft_lsrr.h"
#include "whois.h"

#if defined(__FreeBSD__)
#include <sys/queue.h>
#elif !defined(DARWIN) && !defined(NETBSD)
#include "lft_queue.h"
#endif

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS 0
#endif

#ifdef	__cplusplus
extern "C" {
#endif
/* holds the pseudo-header for generating checksums */
struct sumh
{
    unsigned int src;
    unsigned int dst;
    unsigned char fill;
    unsigned char protocol;
    unsigned short len;
};

/* The actual packet data */
struct trace_packet_s
{
    struct ip ip_hdr;
    struct ip_lsrr lsrr;		/* must go here for ip checksum to work */
    struct tcphdr tcp_hdr;
    struct udphdr udp_hdr;
    int size;
    char *payload;
    int payload_len;
};

/* RFC 1393 type trace IP option */
struct rfc1393_ip_option_s
{
	u_char optcode;		//=82
	u_char optlength;	//=12
	u_short id;			//number to identify icmp trace messages
	u_short ohc;			//outbound hop count
	u_short rhc;			//return hop count
	struct in_addr origip;		//originator ip address
} __attribute__((packed));
/* ICMP echo header */
struct icmp_echo_header_s
{
	u_char type;
	u_char code;
	u_short checksum;
	u_short id;
	u_short sequence;
} __attribute__((packed));
/* ICMP trace response header */
struct icmp_trace_reply_header_s
{
	u_char type;
	u_char code;
	u_short checksum;
	u_short id;
	u_short unused;
	u_short ohc;			//outbound hop count
	u_short rhc;			//return hop count
	u_long ols;				//output link speed
	u_long olmtu;			//output link MTU
} __attribute__((packed));
/* Trace packet for RFC 1393 type and ICMP base trace */
struct icmp_trace_packet_s
{
	char * packet;
	int packet_len;
	struct ip * ip_hdr;
	struct rfc1393_ip_option_s * icmp_trace_opt;
    struct ip_lsrr * lsrr;
	struct icmp_echo_header_s * echo;
    char * payload;
    int payload_len;
};

/* Packet container with additional info */
struct trace_packet_info_s
{
    int icmp_type;		/* ICMP_UNREACH code, -1 if RST reply */
    int is_done;		/* is this a final hop? */
    short hopno;
    unsigned int   seq;
    struct timeval sent;
    struct timeval recv;		/* 0 if unreceived */
    struct in_addr hopaddr;     /* IP address of router */
	/* copy of EvtPacketInfoParam */
	int asnumber;
	char netname[512];
	struct in_addr last_hop;
	/*----------------------------*/
	union
	{
	    struct trace_packet_s packet;
		struct icmp_trace_packet_s icmp_packet;
	} u;
    SLIST_ENTRY(trace_packet_info_s) next_by_hop;
    SLIST_ENTRY(trace_packet_info_s) next;
};

/* hop information, by ttl */
struct hop_info_s
{
    int num_sent;
    int all_sent, all_rcvd;
    struct timeval ts_last_sent;
    struct timeval ts_last_recv;	
	struct trace_packet_info_s * done_packet;
    unsigned short state;
    unsigned short flags;
    SLIST_HEAD(hop_packets_s, trace_packet_info_s) packets;
};

#ifdef	__cplusplus
}
#endif

#endif /*LFT_TYPES_H*/
