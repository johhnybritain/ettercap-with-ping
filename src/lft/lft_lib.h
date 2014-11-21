/*
 *  lft_lib.h
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
#ifndef LFT_LIB_H
#define LFT_LIB_H

#include "lft_types.h"

/* not available in earlier darwin systems */
#ifndef AI_NUMERICSERV 
#define AI_NUMERICSERV 0 
#endif 

/* As the trace progresses, each hope will attempt
to work through the states one by one until it
receives an answer (2 attempts per state).
Whatever state "works" - will be then set up on 
following hops to continue from.
*/
#define HS_SEND_FIN         0x00
#define HS_SEND_SYN         0x01
#define HS_SEND_SYN_FIN     0x02    
#define HS_SEND_RST         0x04
#define HS_SEND_SYN_ACK     0x12
#define HS_SEND_ACK         0x16
#define HS_MAX              (HS_SEND_SYN)

#define HF_ENDPOINT         0x01

/* default timeout value */
#define DEFAULT_TIMEOUT_MS  250 

/* Common EtherType values */
#ifndef ETHERTYPE_IP
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#endif
#ifndef ETHERTYPE_ARP
#define	ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#endif
#ifndef ETHERTYPE_REVARP
#define	ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */
#endif
#ifndef ETHERTYPE_VLAN
#define	ETHERTYPE_VLAN		0x8100	/* IEEE 802.1Q VLAN tagging */
#endif
#ifndef ETHERTYPE_IPV6
#define	ETHERTYPE_IPV6		0x86dd	/* IPv6 */   
#endif

/* Sometimes-missing BPF values */
#ifndef DLT_RAW
#define DLT_RAW         101     /* Raw IP */
#endif
#ifndef DLT_PPP_SERIAL
#define DLT_PPP_SERIAL  50      /* PPP with HDLC encapsulation */
#endif
#ifndef DLT_PPP_ETHER
#define DLT_PPP_ETHER   51      /* PPP over Ethernet */
#endif
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL   113     /* Linux cooked capture */
#endif
#ifndef DLT_PPP
#define DLT_PPP         9       /* PPP over Ethernet */
#endif


/* ToS (type of service) bits we can set on the IP datagram */

#define TOSMINDELAY         0x10
#define TOSMAXTHROUGH       0x08
#define TOSMAXRELIABLE      0x04
#define TOSMINCOST          0x02

/*Errors and warnings codes*/
#define WRN_CANT_SETUP_FIN              -1
#define WRN_CANT_DISP_HOST_NAMES        -2
#define WRN_ADAPTIVE_DISABLED_BY_UDP    -3
#define WRN_FIN_DISABLED_BY_UDP         -4
#define WRN_ONLY_ONE_ASN_LOOKUP         -5
#define WRN_UDP_PORT_TOO_HIGH           -6
#define WRN_PACKET_LENGTH_TOO_HIGH      -7
#define WRN_PACKET_LENGTH_TOO_LOW       -8
#define WRN_CANT_DISABLE_RESOLVER       -9
#define WRN_ALREADY_RANDOM_SPORT        -10
#define WRN_ADAPTIVE_DISABLED_BY_FIN    -12
#define ERR_DEVNAME_TOO_LONG            -13
#define WRN_UNABLE_SETUP_UTC            -14

#define WRN_GETIFFORREMOTE_SOCKET       -15
#define WRN_GETIFFORREMOTE_CONNECT      -16
#define WRN_GETIFFORREMOTE_SOCKNAME     -17
#define ERR_UNKNOWN_HOST                -18
#define ERR_RAW_SOCKET                  -19
#define ERR_SOCKET_BIND                 -20
#define WRN_WSAIOCTL                    -21
#define ERR_IP_HDRINCL                  -22
#define ERR_NOT_ENOUGH_MEM              -23
#define ERR_RAW_TCP_DISABLED            -24

typedef struct _badhopstateparam
{
    const struct hop_info_s *h;
    short nhop;
}WrnBadHopStateParam;
#define WRN_BAD_HOP_STATE               -25
#define WRN_NS_LOOKUP_FAILED            -26
#define ERR_WIN_SELECT                  -27
#define ERR_WIN_RECV                    -28
#define ERR_WIN_WSASTARTUP              -29
#define ERR_PCAP_ERROR                  -30
#define ERR_DISCOVER_INTERFACE          -31
#define ERR_UNKNOWN_INTERFACE           -32
#define ERR_UNKNOWN_SEND_INTERFACE      -32
#define ERR_PCAP_DEV_UNAVAILABLE        -33
#define WRN_BIOCIMMEDIATE               -34
#define ERR_PCAP_NONBLOCK_ERROR         -35
/*Events codes and their params structures*/
#define EVT_AUTOCONFIGURED_TO_PORTS     1
#define EVT_ADDRESS_INITIALIZED         2
typedef struct _sentpacketparams
{
    short nhop;
    unsigned int tseq;
    unsigned char flags;
    unsigned short tttl;
}EvtSentPacketParam;
#define EVT_SENT_PACKET                 3
#define EVT_SHOW_PAYLOAD                4
#define EVT_SHOW_UDP_CHECKSUM           5
#define EVT_SHOW_TCP_CHECKSUM           6
#define EVT_SHOW_HOPS                   7
#define EVT_SHOW_NUM_HOPS               8
#define EVT_TRACE_COMPLETED             9
#define EVT_ON_RESOLUTION               10
#define EVT_TRACE_REPORT_START          11
typedef struct _rptnoreplyparams
{
    int hopno;
    int noreply;
}EvtNoReplyParam;
#define EVT_RPT_NO_REPLY                12
#define EVT_RPT_FRW_INSPECT_PACKS       13
#define EVT_RPT_FRW_STATE_FILTER        14
#define EVT_RPT_BSD_BUG                 15
#define EVT_RPT_HOP_INFO_START          16
typedef struct _packetinfoevtparam
{
    int asnumber;
    const char * netname;
    struct in_addr last_hop;
	int is_asseam;
	int is_netseam;
	int seam_traced;
	int is_open;
	int is_filtered;
    const struct trace_packet_info_s * tp;
}EvtPacketInfoParam;
#define EVT_RPT_PACKET_INFO             17
#define EVT_RPT_PACKET_LIST_END         18
#define EVT_RPT_NO_HOPS                 19
#define EVT_RPT_TIME_TRACE              20
#define EVT_ON_EXIT                     21
#define EVT_TTL_NO_REPLY                22
#define EVT_PROGRESS_NO_REPLY           23
#define EVT_TTL_TOUT_RESEND             24
#define EVT_TTL_TOUT_GIVINGUP           25
typedef struct _debugchkpoint1
{
    int last_return;
    int no_reply;
    int need_reply;
}EvtDebugCheckpoint1Param;
#define EVT_DBG_CHECKPOINT1             26
#define EVT_CANT_RELIABLY_RTRIP         27
#define EVT_HAVE_UNANSWERRED_HOPS       28
#define EVT_TOO_FAR_AHEAD               29
#define EVT_HAVE_GAPS                   30
#define EVT_EITHER_RESP_OR_TOUT         31
#define EVT_LOOKFOR_UNINC_ACK           32
#define EVT_LOOKFOR_OFF_BY_LEN          33
#define EVT_LOOKFOR_LAST_RESORT         34
#define EVT_SKIP_PACKET                 35
typedef struct _nonseqpack
{
    struct in_addr ipaddr;
    const struct trace_packet_info_s * tp;
}EvtNonSeqPacketParam;
#define EVT_ACK_WAS_NOT_INC             36
#define EVT_RST_REL_TO_ISN              37
#define EVT_ACK_WAS_WAY_OFF             38
#define EVT_DUPLICATE_PACKET            39
#define EVT_PROGRESS_DUPLICATE          40
typedef struct _recvpacket
{
    struct in_addr ipaddr;
	struct trace_packet_info_s * tp;
    unsigned int seq;
}EvtRecvPacketParam;
#define EVT_RECV_PACKET                 41
#define EVT_PROGRESS_OK                 42
#define EVT_TCP_PORT_CLOSED             43
#define EVT_TCP_PORT_OPEN               44
#define EVT_PROCESS_PACKET_START        45
#define EVT_UDP_NOT_FOR_US              46
typedef struct _incomudpicmp
{
    const struct ip * ip;
    const struct ip * orig_ip;
    const struct udphdr *udp;
    const struct icmp *icmp;
}EvtIncomingICMPUDPParam;
#define EVT_INCOMING_ICMP_UDP           47
#define EVT_RCVD_ICMP_UDP               48
typedef struct _incomtcpicmp
{
    const struct ip * ip;
    const struct ip * orig_ip;
    const struct tcphdr *tcp;
    const struct icmp *icmp;
}EvtIncomingICMPTCPParam;
#define EVT_INCOMING_ICMP_TCP           49
#define EVT_RCVD_ICMP_TCP               50
#define EVT_RCVD_TCP                    51
#define EVT_RCVD_UNKNOWN                52
#define EVT_DEVICE_SELECTED             53
#define EVT_SHOW_INITIAL_SEQNUM         54
#define EVT_TRACE_START                 55
#define EVT_DBG_CHECKPOINT2             56

#define EVT_DBG_LOG_MESSAGE             57

#define EVT_PROGRESS_SKIP_PACKET	58

#define EVT_OPEN_CHECK_RESULT		59

#define ERR_BTCP_PROBE_PORT_IS_BUSY	60
#define ERR_BTCP_WRONG_PORT_VALUE	61

#define EVT_OCHECK_START		62
#define WRN_OCHECK_OPEN_SOCK		63
#define WRN_OCHECK_IOCTL		64
#define WRN_OCHECK_SELECT		65
#define WRN_OCHECK_GETERROR		66
#define WRN_OCHECK_SOCKERROR		67
#define WRN_OCHECK_TIMEOUT		68
#define EVT_OCHECK_OPEN			69
#define WRN_OCHECK_FCNTLGET		70
#define WRN_OCHECK_FCNTLSET		71
#define WRN_OCHECK_CONNECTERR		72

typedef struct _incomechoreplyicmp
{
    const struct ip * ip;
    const struct icmp_echo_header_s * echo;
}EvtIncomingICMPEchoParam;
#define EVT_INCOMING_ICMP_Echo		73
#define EVT_RCVD_ICMP_Echo		74

typedef struct _incomicmpicmp
{
    const struct ip * ip;
	const struct icmp * icmp;
	const struct ip * orig_ip;
    const struct icmp_echo_header_s * echo;
}EvtIncomingICMPICMPParam;
#define EVT_INCOMING_ICMP_ICMP		75
#define EVT_RCVD_ICMP_ICMP		76

#if defined(BSD_IP_STACK) && !defined(OPENBSD)
#define SCREWED_IP_LEN
#endif

typedef struct btcpmapentry
{
	int nhop;
	int port;
	int sentcount;
}BasicTCPMapEntry;
#ifdef	__cplusplus
extern "C" {
#endif
typedef struct _btcp_debug_info
{
	int type;
	int hop;
	int phop;
	int port;
	struct in_addr ip;
}btcp_debug_info;
/* Session parameters */
typedef struct _lft_session_params
{
    struct timeval ts_last_sent;
    struct timeval now;
    double scatter_ms;                      /* milleseconds between sends */
    int ttl_min;                            /* user may request to start at a higher TTL */
    int hop_info_length;

    unsigned short ip_id;                   /*not used*/
    unsigned char tcp_flags;

    int use_fins;

    int seq_start;       /* generate ISN internally by default */
    int dport;           /* set default destination to tcp/80 HTTP */
    int sport;           /* set default source to tcp/53 dns-xfer */
    int auto_ports;      /* enable port autoselection by default */
    int random_source;   /* disable random source port by default */
    int set_tos;         /* disable set ToS bit by default */
    int userlen;         /* user-requested packet length */
    int payloadlen;      /* the final probe payloadlength */
    int win_len;

    int timeout_ms;      /* timeout between retries */
    int retry_max;       /* number of retries before giving up */
    int retry_min;       /* minimum number of checks per hop */
    int ahead_limit;     /* number of probes we can send
                          * without replies if we don't know
                          * the number of hops */
    int dflag;

    int ttl_limit;       /* max # hops to traverse (highest TTL) */
    int break_on_icmp;	 /* break on icmp other than time exceeded */
    int noisy;           /* disable verbose debug by default */
    int nostatus;        /* print status bar by default */
    int userdevsel;      /* by default, we'll select the device */
    int senddevsel;      /* by default, we'll select the device */
    int resolve_names;   /* dns resolution enabled by default */
    int hostnames_only;	 /* disable printing of IP addresses */
    int timetrace;       /* disable tracer timing by default */
    int adaptive;		 /* disable state engine by default */
	int protocol;		 /* 0 - TCP, 1 - UDP, 2 - ICMP base, 3 - ICMP RFC 1393, 4 - TCP basic */
    int do_netlookup;    /* disable netname lookup by default */
    int do_aslookup;     /* disable asn lookup by default */
    int use_radb;        /* use RADB instead of pwhois */
    int use_cymru;       /* use Cymru instead of pwhois */
    int use_ris;         /* use RIPE NCC RIS instead of pwhois */

    char *payload;

    int send_sock;
    int skip_header_len;

#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
    int recv_sock;
    int wsastarted;
#else
    pcap_t * pcapdescr;
#endif
    int UseLocalTime;

    int num_hops;
    /*int num_sent;*/
    int num_rcvd;
    int target_open;
	int target_filtered;
    int target_anomaly;

    char *hostname;
    char *hostname_lsrr[9];
    int hostname_lsrr_size;

    struct in_addr local_address;
    struct in_addr remote_address;

    struct timeval begin_time, trace_done_time;

    /* The actual packet data (one of..)*/
    struct trace_packet_s trace_packet;
	struct icmp_trace_packet_s icmp_packet;

    /* Packet container with additional info */
    /* struct trace_packet_info_s * trace_packet_info;*/		/* indexed by dport - dport NOT USED*/

    /* list of packet containers */
    SLIST_HEAD(packets_s, trace_packet_info_s) trace_packets;
    int trace_packets_num;

	/* Map of ports for basic TCP trace */
	BasicTCPMapEntry * btcpmap;
	int latestmapchoice;
	int btcpmapsize;
	int btcpdpucnt;
	int trg_probe_is_sent;
	/* btcp_debug_info debugmap[1000]; */
	/* int debugmapidx; */
	
    /* hop information, by ttl */
    struct hop_info_s * hop_info;
    const char * pcap_dev;
    /* data link type as in pcap_datalink() */
    int pcap_datalink;
    const char * pcap_send_dev;
    const char * userdev;
    const char * senddev;
    /*WHOIS parameters*/
    whois_session_params * wsess;
    /*User's data*/
    void * UsersDataCookie;

	/* GraphViz subquery. Disables any output. */
	int is_graphviz_subquery;
	int check_seam;
	char * graphviz_icon_path;
    /*Exit status. When this field has value <0 lft will end work as soon as possible*/
    int exit_state;
}lft_session_params;

extern const char * icmp_messages[];
extern const char *version;
extern const char *appname;
extern const int maxpacklen;
/*--------------------------- Callbacks definition ---------------------------*/
/*
Paramaters: 
    lft_session_params * sess - session handle, 
    int code - code of error or event,
    const void * param - additional parameters, depend on code
*/
typedef void (*LFT_CALLBACK)(lft_session_params *, int, const void *);
/*----------------------------------------------------------------------------*/
void LFTInitializeCallbacks(LFT_CALLBACK error_handler, LFT_CALLBACK event_handler);
lft_session_params * LFTSessionOpen(void);
void LFTSessionClose(lft_session_params * sess);
double timediff_ms (struct timeval prior, struct timeval latter);
unsigned int get_address(lft_session_params * sess, const char *host);
#ifndef SCREWED_IP_LEN 
u_int32_t ip_cksum (const struct ip *ip);
#endif
u_int32_t tcp_cksum (struct ip *ip, struct tcphdr *tcp, const char * payload, int payload_len);
int hop_state_up (lft_session_params * sess, short nhop);
int hop_state_copy(lft_session_params * sess, short nhop);
unsigned int new_seq(lft_session_params * sess);
/*----------------------------------------------------------------------------*/
/*                          Safe setting of parameters                        */
/*----------------------------------------------------------------------------*/
/*Use TCP FIN packets exclusively (defaults are SYN)*/
int LFTSetupFIN(lft_session_params * sess);
/*Display hosts symbolically; suppress IP address display*/
int LFTSetupDispSymbHost(lft_session_params * sess);
/*Use traditional UDP (probes) for tracing instead of TCP*/
int LFTSetupUDPMode(lft_session_params * sess);
#define ASN_LOOKUP_RIS      0
#define ASN_LOOKUP_RADB     1
#define ASN_LOOKUP_CYMRU    2
/*Use RIPE NCC's RIS to resolve ASNs instead of Prefix WhoIs*/
int LFTSetupRISLookup(lft_session_params * sess);
/*Use the RADB to resolve ASNs instead of Prefix WhoIs*/
int LFTSetupRADBLookup(lft_session_params * sess);
/*Use Cymru to resolve ASNs instead of Prefix WhoIs*/
int LFTSetupCYMRULookup(lft_session_params * sess);
/*Destination port number (same as using target:port as target)*/
int LFTSetupDestinationPort(lft_session_params * sess, char * userport);
/*Set the length of the probe packet in bytes*/
int LFTSetupLengthOfPacket(lft_session_params * sess, int plen);
/*Display hosts numerically; disable use of the DNS resolver*/
int LFTSetupDisableResolver(lft_session_params * sess);
/*Source port number*/
int LFTSetupSourcePort(lft_session_params * sess, int port);
/*Use LFT's stateful engine to detect firewalls and path anomalies*/
int LFTSetupAdaptiveMode(lft_session_params * sess);
/*Use a specific device by name or IP address (\"en1\" or \"1.2.3.4\")*/
int LFTSetupDevice(lft_session_params * sess,char * udev);
/*Use a specific device by name or IP address (\"en1\" or \"1.2.3.4\")*/
int LFTSetupSendDevice(lft_session_params * sess,char * sdev);
/*Display all times in UTC (GMT0).  Activates -T option automatically*/
int LFTSetupUTCTimes(lft_session_params * sess);
/*----------------------------------------------------------------------------*/
int lft_resolve_port (lft_session_params * sess, const char *strport);
void LFTExecute(lft_session_params * sess);
void lft_printf(lft_session_params * sess, const char *templ, ...);
/*----------------------------------------------------------------------------*/
void setOutputStyle(int nstyle); /* 0 - ordinary output, 1 - xml output */
int outputStyleIsXML(void);
int outputStyleIsGraphViz(void);
int getOutputStyle(void);
/*----------------------------------------------------------------------------*/
#ifdef	__cplusplus
}
#endif

#endif /*LFT_LIB_H*/
