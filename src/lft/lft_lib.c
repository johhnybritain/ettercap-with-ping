/*
 *  lft_lib.c
 *  Layer Four Traceroute
 *
 *  This file is part of LFT.
 *
 *  The LFT software provided in this Distribution is
 *  Copyright 2010 VOSTROM Holdings, Inc.
 *
 *  The full text of our legal notices is contained in the file called
 *  COPYING, included with this Distribution.
 *
 */

#define _USE_32BIT_TIME_T

#include "lft_lib.h"
#include "lft_btcptrace.h"
#include "lft_icmptrace.h"

/*---------------------------------------------------------------------------*/
/* GraphViz output defines */
#define GVGRAPHNAME				"lftpath"
/*
#define GVHOPSTYLE_BASE				"shape = rect, penwidth=1"
#define GVHOPSTYLE_SOURCE			"shape = rect, style=filled, fillcolor=lightskyblue, color=skyblue, penwidth=2"
#define GVHOPSTYLE_TARGET_OPEN			"shape = rect, style=filled, fillcolor=palegreen, color=mediumspringgreen, penwidth=2"
#define GVHOPSTYLE_TARGET_CLOSED		"shape = rect, style=filled, fillcolor=tomato, color=orangered, penwidth=2"
#define GVHOPSTYLE_TARGET_FILTERED		"shape = rect, style=filled, fillcolor=grey, color=mediumspringgreen, penwidth=2"
#define GVHOPSTYLE_HOLE				"shape = note, style=filled, fillcolor=lightgrey, color=slategrey, penwidth=2"
#define GVHOPSTYLE_ANOMALY1			"shape = rect, style=filled, fillcolor=salmon, skew=.4, color=orangered, penwidth=2"
#define GVHOPSTYLE_ANOMALY2			"shape = rect, style=filled, fillcolor=lemonchiffon, skew=.4, color=orangered, penwidth=2"
#define GVHOPSTYLE_ANOMALY3			"shape = rect, style=filled, fillcolor=lightgrey, color=slategrey, skew=.4, penwidth=2"
*/
#define GVHOPSTYLE_BASE					"shape = none"
#define GVHOPSTYLE_SOURCE				"shape = none"
#define GVHOPSTYLE_TARGET_OPEN			"shape = none"
#define GVHOPSTYLE_TARGET_CLOSED		"shape = none"
#define GVHOPSTYLE_TARGET_FILTERED		"shape = none"
#define GVHOPSTYLE_HOLE					"shape = none"
/* Firewall - The next gateway may statefully inspect packets */
#define GVHOPSTYLE_ANOMALY1				"shape = none"
/* Firewall - The next gateway may implement a flag-based state filter */
#define GVHOPSTYLE_ANOMALY2				"shape = none"
/* 4.2-3 BSD bug - The next gateway may errantly reply with reused TTLs */
#define GVHOPSTYLE_ANOMALY3				"shape = none"

#define GV_ANOMALY1_TEXT	"Stateful Firewall"
#define GV_ANOMALY2_TEXT	"Flag-based Firewall"
#define GV_ANOMALY3_TEXT	"BSD-stack TTL Reused"

#define GVFONTSIZE				"12"
#define GVFONTNAME				"Helvetica"

static const char GVNTBEG[]="<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\"><tr><td><img src=\"";
static const char GVNTMID[]="\"/></td></tr><tr><td>";
static const char GVNTEND[]="</td></tr></table>";
static const char GVNIMG_SOURCE[]="source.png";
static const char GVNIMG_TRGOPEN[]="dest.png";
static const char GVNIMG_TRGCLOSED[]="dest_closed.png";
static const char GVNIMG_TRGFILTERED[]="dest_prohibited.png";
static const char GVNIMG_ANOMALY1[]="firewall_smart.png";
static const char GVNIMG_ANOMALY2[]="firewall_stupid.png";
static const char GVNIMG_ANOMALY3[]="firewall_stupid.png";
static const char GVNIMG_REGULAR[]="router.png";
static const char GVNIMG_HOLE[]="router_cloaked.png";
static const char GVNIMG_SEAM[]="router_seam.png";
#if defined(WIN32) || defined(_WIN32)
static const char DIRECTORY_SPLITTER='\\';
#else
static const char DIRECTORY_SPLITTER='/';
#endif
/*---------------------------------------------------------------------------*/
static const int start_dport = 33434;  /* starting port for UDP tracing (traceroute 
                                   compatibility for some targets that care */
const int maxpacklen = 16 * 1024;  /* maximum user-supplied probe length */
                                    /* Ethernet=1500, GigEther(jumbo)=9000 */
static const int minpacklen = 60;     /* minimum user-supplied probe length */

const char * icmp_messages[] = {
    "endpoint",
    "net unreachable",
    "host unreachable",
    "protocol unreachable",
    "port unreachable",
    "need fragment",
    "source fail",
    "net unknown",
    "host unknown",
    "src isolated",
    "net prohib",
    "host prohib",
    "bad tos/net",
    "bad tos/hst",
    "prohibited",
    "precedence violation",
    "precedence cutoff"
};

static char time_format[] = "%d-%b-%y %H:%M:%S %Z"; /* time display format */
static char tbuf[128];
const char *appname = "LFT";
static const int hop_info_size = 256;  /* can't be more than this */

static const unsigned int max_net_dev_input = 64; /* only take this much input */

static const int def_payload_len = 10;     /* default payload length for UDP packets */

#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
static int sock = -1;
#endif

static int global_output_style=0;	/* 0 - ordinary output, 1 - xml output, 2 - GraphViz output */

void GraphVizOutput(lft_session_params * sess);

/*---------------------------------------------------------------------------*/
static void LFTDefaultErrorHandler(lft_session_params * sess, int code, const void * params)
{
    const WrnBadHopStateParam * wbhsp;
    switch(code)
    {
    case WRN_CANT_SETUP_FIN:
		if(global_output_style==1)
			printf("<warning code=\"%d\">%s</warning>",code,
				   "TCP flags are selected automatically using (-E) option.\n\t\t\tIgnoring FINs-only (-F) option and using adaptive Engine.\n");
		else
			fprintf (stderr,
					 "LFT warning: TCP flags are selected automatically using (-E) option.\n\t\t\tIgnoring FINs-only (-F) option and using adaptive Engine.\n");
        break;
    case WRN_CANT_DISP_HOST_NAMES:
		if(global_output_style==1)
			printf("<warning code=\"%d\">%s</warning>",code,
				   "I can't display hostnames (-h) unless I resolve them.\n\t\t\tIgnoring your request to display hostnames exclusively.\n");
		else
			fprintf (stderr,
					 "LFT warning: I can't display hostnames (-h) unless I resolve them.\n\t\t\tIgnoring your request to display hostnames exclusively.\n");
        break;
    case WRN_ADAPTIVE_DISABLED_BY_UDP:
		if(global_output_style==1)
			printf("<warning code=\"%d\">%s</warning>",code,"Disabling adaptive mode while using UDP.");
		else
			fprintf (stderr,"LFT warning: Disabling adaptive mode while using UDP.\n");
        break;
    case WRN_FIN_DISABLED_BY_UDP:
		if(global_output_style==1)
			printf("<warning code=\"%d\">%s</warning>",code,"Disabling FINs-only mode while using UDP.");
		else
			fprintf (stderr,"LFT warning: Disabling FINs-only mode while using UDP.\n");
        break;
    case WRN_ONLY_ONE_ASN_LOOKUP:
		if(global_output_style==1)
			printf("<warning code=\"%d\">%s",code,"Only one ASN lookup source may be used--you selected ");
		else
			fprintf (stderr,"LFT warning: Only one ASN lookup source may be used--you selected ");
		if(global_output_style!=1)
		{
			if(sess->use_cymru)
				fprintf (stderr,"Cymru.\n\t\t\tIgnoring your request to use ");
			if(sess->use_ris)
				fprintf (stderr,"RIPE NCC RIS.\n\t\t\tIgnoring your request to use ");
			if(sess->use_radb)
				fprintf (stderr,"RADB.\n\t\t\tIgnoring your request to use ");
			switch(*((const int *)params))
			{
				case ASN_LOOKUP_RIS:
					fprintf (stderr,"RIPE NCC RIS.\n");
					break;
				case ASN_LOOKUP_RADB:
					fprintf (stderr,"RADB.\n");
					break;
				case ASN_LOOKUP_CYMRU:
					fprintf (stderr,"Cymru.\n");
					break;
			}
			if(global_output_style==1)
				printf("</warning>");
		}
		break;
    case WRN_UDP_PORT_TOO_HIGH:
			if(global_output_style==1)
				printf("<warning code=\"%d\">Starting UDP port %d is too high.  Will start with %d instead.</warning>",
					   code, *((const int *)params), sess->dport);
			else
				fprintf (stderr,
						 "LFT warning: Starting UDP port %d is too high.  Will start with %d instead.\n", *((const int *)params), sess->dport);
			break;
    case WRN_PACKET_LENGTH_TOO_HIGH:
			if(global_output_style==1)
				printf("<warning code=\"%d\">Packet length %d is too high.  Will use %d instead.</warning>",
					   code, *((const int *)params), maxpacklen);
			else
				fprintf (stderr,
						 "LFT warning: Packet length %d is too high.  Will use %d instead.\n", *((const int *)params), maxpacklen);
			break;
    case WRN_PACKET_LENGTH_TOO_LOW:
			if(global_output_style==1)
				printf("<warning code=\"%d\">Packet length %d is too low.  Will use %d instead.</warning>",
					   code, *((const int *)params), minpacklen);
			else
				fprintf (stderr,
						 "LFT warning: Packet length %d is too low.  Will use %d instead.\n", *((const int *)params), minpacklen);
			break;
    case WRN_CANT_DISABLE_RESOLVER:
			if(global_output_style==1)
				printf("<warning code=\"%d\">%s</warning>",code,
					   "LFT warning: I can't display hostnames (-h) unless I resolve them.\n\t\t\tIgnoring your request not to resolve DNS.\n");
			else
				fprintf (stderr,
						 "LFT warning: I can't display hostnames (-h) unless I resolve them.\n\t\t\tIgnoring your request not to resolve DNS.\n");
			break;
    case WRN_ALREADY_RANDOM_SPORT:
			if(global_output_style==1)
				printf("<warning code=\"%d\">%s</warning>",code,
					   "LFT warning: You already asked to use a random source port.\n\t\t\tIgnoring request to set specific source port.\n");
			else
				fprintf (stderr,
						 "LFT warning: You already asked to use a random source port.\n\t\t\tIgnoring request to set specific source port.\n");
			break;
    case WRN_ADAPTIVE_DISABLED_BY_FIN:
			if(global_output_style==1)
				printf("<warning code=\"%d\">%s</warning>",code,
					   "LFT warning: TCP flags are selected automatically using (-E) option.\n\t\t\tIgnoring adaptive Engine (-E) option and using FINs-only (-F).\n");
			else
				fprintf (stderr,
						 "LFT warning: TCP flags are selected automatically using (-E) option.\n\t\t\tIgnoring adaptive Engine (-E) option and using FINs-only (-F).\n");
			break;
    case ERR_DEVNAME_TOO_LONG:
			if(global_output_style==1)
				printf("<error code=\"%d\">Net interface names are limited to %d characters. (e.g., \"eth0\" or \"ppp0\" or \"10.10.10.10\")</error>",code,
					   max_net_dev_input);
			else
				fprintf (stderr,
						 "Net interface names are limited to %d characters. (e.g., \"eth0\" or \"ppp0\" or \"10.10.10.10\")\n",
						 max_net_dev_input);
			sess->exit_state=-1;
			break;
    case WRN_UNABLE_SETUP_UTC:
			if(global_output_style==1)
				printf("<warning code=\"%d\">%s</warning>",code,"Unable to set TZ to UTC.");
			else
				fprintf(stderr, "LFT: Unable to set TZ to UTC.\n");
			break;
    case ERR_UNKNOWN_HOST:
			if(global_output_style==1)
				printf("<error code=\"%d\">Unknown host: %s</error>",code,(const char *)params);
			else
				fprintf (stderr, "LFT: Unknown host: %s\n", (const char *)params);
			sess->exit_state=-2;
			break;
    case WRN_GETIFFORREMOTE_SOCKET:
			if(global_output_style==1)
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
				printf("<warning code=\"%d\">socket: %s</warning>",code,strerror(errno));
#else
			printf("<warning code=\"%d\">Socket trouble; unable to determine interface</warning>",code);
#endif
			else
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
				perror("socket");
#else
			perror("LFT: Socket trouble; unable to determine interface");
#endif
			break;
    case WRN_GETIFFORREMOTE_CONNECT:
			if(global_output_style==1)
				printf("<warning code=\"%d\">UDP connect(); unable to determine interface: %s</warning>",code,strerror(errno));
			else
				perror("LFT: UDP connect(); unable to determine interface");
			break;
    case WRN_GETIFFORREMOTE_SOCKNAME:
			if(global_output_style==1)
				printf("<warning code=\"%d\">getsockname: %s</warning>",code,strerror(errno));
			else
				perror("getsockname");
			break;
    case ERR_RAW_SOCKET:
			if(global_output_style==1)
				printf("<error code=\"%d\">raw socket: %s</error>",code,strerror(errno));
			else
				perror ("LFT: raw socket");
			sess->exit_state=-3;
			break;
    case ERR_SOCKET_BIND:
			if(global_output_style==1)
				printf("<error code=\"%d\">bind: %s</error>",code,strerror(errno));
			else
				perror ("LFT: bind");
			sess->exit_state=-4;
			break;
    case WRN_WSAIOCTL:
			if(global_output_style==1)
				printf("<warning code=\"%d\">WSAIoctl: %s</warning>",code,strerror(errno));
			else
				perror("LFT: WSAIoctl");
			break;
    case ERR_IP_HDRINCL:
			if(global_output_style==1)
				printf("<error code=\"%d\">IP_HDRINCL: %s</error>",code,strerror(errno));
			else
				perror ("LFT: IP_HDRINCL");
			sess->exit_state=-5;
			break;
    case ERR_NOT_ENOUGH_MEM:
			if(global_output_style==1)
				printf("<error code=\"%d\">malloc(): %s</error>",code,strerror(errno));
			else
				perror("malloc");
			sess->exit_state=-6;
			break;
    case ERR_RAW_TCP_DISABLED:
		if(global_output_style==1)
		{
			printf("<error code=\"%d\">sendto: %s\n",code,strerror(errno));
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
			if (!sess->protocol) {
				printf("Your platform may prevent you from using raw TCP sockets.\n");
				printf("Try UDP-based tracing instead using the \"-u\" option.\n");
			}
#else
			printf("Your platform may prevent you from using raw TCP sockets.\n");
			printf("This could be the result of a local (host-based) firewall\n");
			printf("or a permissions problem on this binary or the BPF device.\n");
			if(sess->adaptive)
				printf("You can try TCP-based tracing without using adaptive mode.\n");
			printf("You can try UDP-based tracing using the \"-u\" option.\n");
#endif
			printf("</error>\n");
		}
		else
		{
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
			perror ("sendto");
			if (!sess->protocol) {
				fprintf(stderr,"LFT:  Your platform may prevent you from using raw TCP sockets.\n");
				fprintf(stderr,"      Try UDP-based tracing instead using the \"-u\" option.\n");
			}
#else
			perror ("sendto");
			fprintf(stderr,"LFT:  Your platform may prevent you from using raw TCP sockets.\n");
			fprintf(stderr,"      This could be the result of a local (host-based) firewall\n");
			fprintf(stderr,"      or a permissions problem on this binary or the BPF device.\n");
			if (sess->adaptive)
				fprintf(stderr,"      You can try TCP-based tracing without using adaptive mode.\n");
			fprintf(stderr,"      You can try UDP-based tracing using the \"-u\" option.\n");
#endif
		}
		sess->exit_state=-7;
        break;
    case WRN_BAD_HOP_STATE:
			wbhsp=(const WrnBadHopStateParam *)params;
			if(global_output_style==1)
				printf("<warning code=\"%d\">Bad state %#x for hop %d</warning>", code, wbhsp->h->state, wbhsp->nhop);
			else
				fprintf(stderr,"Bad state %#x for hop %d\n", wbhsp->h->state, wbhsp->nhop);
			break;
    case WRN_NS_LOOKUP_FAILED:
			if(global_output_style==1)
			{
				printf("<warning code=\"%d\">", code);
				if(sess->use_radb)
					printf ("The RADB lookup failed.");
				else
					if(sess->use_cymru)
						printf ("The Cymru lookup failed.");
					else
						if(sess->use_ris)
							printf ("The RIPE NCC RIS lookup failed.");
						else
							printf ("The Prefix WhoIs lookup failed.");
				printf("</warning>");
			}
			else
			{
				if(sess->use_radb)
					fprintf(stderr,"The RADB lookup failed.\n");
				else
					if(sess->use_cymru)
						fprintf(stderr,"The Cymru lookup failed.\n");
					else
						if(sess->use_ris)
							fprintf(stderr,"The RIPE NCC RIS lookup failed.\n");
						else
							fprintf(stderr,"The Prefix WhoIs lookup failed.\n");
			}
			break;
    case ERR_WIN_SELECT:
			if(global_output_style==1)
				printf("<error code=\"%d\">select: %s</error>",code,strerror(errno));
			else
				perror("select");
			sess->exit_state=-8;
			break;
    case ERR_WIN_RECV:
			if(global_output_style==1)
				printf("<error code=\"%d\">read: %s</error>",code,strerror(errno));
			else
				perror("read");
			sess->exit_state=-9;
			break;
    case ERR_WIN_WSASTARTUP:
			if(global_output_style==1)
				printf("<error code=\"%d\">WSAStartup: %s</error>",code,strerror(errno));
			else
				perror("WSAStartup");
			sess->exit_state=-10;
			break;
    case ERR_PCAP_ERROR:
			if(global_output_style==1)
				printf("<error code=\"%d\">%s</error>",code,(const char *)params);
			else
				fprintf (stderr, "LFT: %s\n", (const char *)params);
			sess->exit_state=-11;
			break;
    case ERR_DISCOVER_INTERFACE:
			if(global_output_style==1)
				printf("<error code=\"%d\">Failed to discover an appropriate interface</error>",code);
			else
				fprintf (stderr, "LFT: Failed to discover an appropriate interface.\n");
			sess->exit_state=-12;
			break;
    case ERR_UNKNOWN_INTERFACE:
			if(global_output_style==1)
				printf("<error code=\"%d\">Unable to locate a local interface with IP address %s</error>",code,sess->userdev);
			else
				fprintf (stderr, "LFT: Unable to locate a local interface with IP address %s\n", sess->userdev);
			sess->exit_state=-13;
			break;
    case ERR_PCAP_DEV_UNAVAILABLE:
			if(global_output_style==1)
				printf("<error code=\"%d\">The network device \"%s\" isn\'t available to LFT.  Try another or fix:\nERROR: %s</error>",code,sess->pcap_dev,(const char *)params);
			else
				fprintf (stderr, "The network device \"%s\" isn\'t available to LFT.  Try another or fix:\nERROR: %s\n", sess->pcap_dev, (const char *)params);
			sess->exit_state=-14;
			break;
	case WRN_BIOCIMMEDIATE:
			if(global_output_style==1)
				printf("<warning code=\"%d\">BIOCIMMEDIATE: %s</warning>", code, (const char *)params);
			else
				fprintf(stderr, "BIOCIMMEDIATE: %s\n",(const char *)params);
			sess->exit_state=-34;
			break;
	case WRN_OCHECK_OPEN_SOCK:
		if(global_output_style!=1 && sess->noisy>1)
			fprintf(stderr, "LFT: Error opening socket.\n");
		if(global_output_style==1)
			printf("<warning code=\"%d\">Error opening socket</warning>", code);
        break;
	case WRN_OCHECK_IOCTL:
		if(global_output_style!=1 && sess->noisy>1)
			fprintf(stderr, "LFT: Error setting nonblocking mode (IOCTL).\n");
		if(global_output_style==1)
			printf("<warning code=\"%d\">Error setting nonblocking mode (IOCTL)</warning>", code);
        break;
	case WRN_OCHECK_SELECT:
		if(global_output_style!=1 && sess->noisy>1)
			fprintf(stderr, "LFT: Error on socket select call.\n");
		if(global_output_style==1)
			printf("<warning code=\"%d\">Error on socket select call</warning>", code);
        break;
	case WRN_OCHECK_GETERROR:
		if(global_output_style!=1 && sess->noisy>1)
			fprintf(stderr, "LFT: Error trying to read socket error.\n");
		if(global_output_style==1)
			printf("<warning code=\"%d\">Error trying to read socket error</warning>", code);
        break;
	case WRN_OCHECK_SOCKERROR:
		if(global_output_style!=1 && sess->noisy>1)
			fprintf(stderr, "LFT: Error on socket.\n");
		if(global_output_style==1)
			printf("<warning code=\"%d\">Error on socket</warning>", code);
        break;
	case WRN_OCHECK_TIMEOUT:
		if(global_output_style!=1 && sess->noisy>1)
			fprintf(stderr, "LFT: Timeout on socket.\n");
		if(global_output_style==1)
			printf("<warning code=\"%d\">Timeout on socket</warning>", code);
        break;
	case WRN_OCHECK_FCNTLGET:
		if(global_output_style!=1 && sess->noisy>1)
			fprintf(stderr, "LFT: Error setting nonblocking mode (FCNTL GET).\n");
		if(global_output_style==1)
			printf("<warning code=\"%d\">Error setting nonblocking mode (FCNTL GET)</warning>", code);
        break;
	case WRN_OCHECK_FCNTLSET:
		if(global_output_style!=1 && sess->noisy>1)
			fprintf(stderr, "LFT: Error setting nonblocking mode (FCNTL SET).\n");
		if(global_output_style==1)
			printf("<warning code=\"%d\">Error setting nonblocking mode (FCNTL SET)</warning>", code);
        break;
	case WRN_OCHECK_CONNECTERR:
		if(global_output_style!=1 && sess->noisy>1)
			fprintf(stderr, "LFT: Error trying socket connect.\n");
		if(global_output_style==1)
			printf("<warning code=\"%d\">Error trying socket connect</warning>", code);
        break;
	case ERR_PCAP_NONBLOCK_ERROR:
			if(global_output_style==1)
				printf("<error code=\"%d\">%s</error>",code,(const char *)params);
			else
				fprintf (stderr, "LFT: Failed to set nonblocking mode.\n     %s\n", (const char *)params);
			sess->exit_state=-35;
			break;
    }
}
/*---------------------------------------------------------------------------*/
static void
print_host (lft_session_params * sess, struct in_addr addr)
{
    struct hostent *h;
    
    if (!sess->resolve_names) {
		if(global_output_style==1)
			printf (" ip=\"%s\"", inet_ntoa (addr));
		else
			printf ("%s", inet_ntoa (addr));
    } else {
        h = gethostbyaddr ((void *) &addr, 4, AF_INET);
        if (h) {
			if(global_output_style==1)
				printf (" host=\"%s\"", h->h_name);
			else
				printf ("%s", h->h_name);
            if (!sess->hostnames_only) 
			{
				if(global_output_style==1)
					printf (" ip=\"%s\"", inet_ntoa (addr));
				else
					printf(" (%s)", inet_ntoa (addr));
			}
        } else
		{
			if(global_output_style==1)
				printf (" ip=\"%s\"", inet_ntoa (addr));
			else
				printf ("%s", inet_ntoa (addr));
		}
    }
}
/*---------------------------------------------------------------------------*/
double timediff_ms (struct timeval prior, struct timeval latter)
{
    return
    (latter.tv_usec - prior.tv_usec) / 1000. +
    (latter.tv_sec - prior.tv_sec) * 1000.;
}
/*---------------------------------------------------------------------------*/
static void EvtPacketInfoDefaultHandler(lft_session_params * sess, const EvtPacketInfoParam * ehip)
{
    char ind=' ';
	
    if(ehip->tp->recv.tv_sec) {
        if (ehip->last_hop.s_addr != ehip->tp->hopaddr.s_addr) {
            if (sess->do_aslookup) {
				if(global_output_style==1)
					printf(" asn=\"%d\"", ehip->asnumber);
				else
				{
					if (ehip->asnumber)
						printf(" [%d]", ehip->asnumber);
					else
						printf(" [AS?]");
				}
            }
            if (sess->do_netlookup) {
				if(global_output_style==1)
					printf(" net=\"%s\"", ehip->netname);
				else
				{
					if(ehip->netname && strlen(ehip->netname)>0)
						printf(" [%s]", ehip->netname);
					else
						printf(" [Net?]");
				}
            }
            if (ehip->tp->icmp_type < -2 || ehip->tp->icmp_type > 17)
			{
				if(global_output_style==1)
					printf(" icmpcode=\"%d\"", ehip->tp->icmp_type);
				else
					printf (" [icmp code %d]", ehip->tp->icmp_type);
			}
            else 
                if (ehip->tp->icmp_type >= 0)
				{
					if(global_output_style==1)
						printf (" icmpmsg=\"%s\"", icmp_messages[ehip->tp->icmp_type + 1]);
					else
						printf (" [%s]", icmp_messages[ehip->tp->icmp_type + 1]);                    
				}
                    
            if (ehip->tp->icmp_type == -1) {
				if(global_output_style==1)
					printf(" trgstate=\"");
				else
					printf(" [target");
				if(sess->protocol==0 || sess->protocol==4)
				{
					if(!global_output_style==1)
						printf(" ");
					if (sess->target_open > 0)
						printf("open");
					else
					{
						if(sess->target_filtered > 0)
							printf("filtered");
						else
							printf("closed");
					}
				}
				if(global_output_style==1)
					printf("\"");
				else
					printf("]");
            }
			if(ehip->is_asseam)
			{
				if(global_output_style==1)
					printf(" asseam=\"1");
				else
					printf(" (AS-Method Seam");
			}
			if(ehip->is_netseam)
			{
				if(global_output_style==1)
					printf(" netseam=\"1");
				else
				{
					if(ehip->is_asseam)
					   printf(", Network-Method Seam");
					else
					   printf(" (Network-Method Seam");
				}
			}
			if(ehip->is_asseam || ehip->is_netseam)
			{
				if(ehip->seam_traced)
				{
					if(global_output_style==1)
						printf("\" seamstate=\"");
					else
						printf(": ");
					if(ehip->is_open)
						printf("OPEN");
					else
					{
						if(ehip->is_filtered)
							printf("FILTERED");
						else
							printf("CLOSED");
					}
				}
				if(global_output_style==1)
					printf("\"");
				else
					printf(")");
			}
			if(global_output_style!=1)
				printf(" ");
            print_host (sess, ehip->tp->hopaddr);
            if (ehip->tp->icmp_type == -1 && (sess->protocol<2 || sess->protocol>3))
			{
				if(global_output_style==1)
					printf(" port=\"%d\"",sess->dport);
				else
					printf(":%d",sess->dport);
            }
        }
        else
		{
			if(global_output_style==1)
				ind=';';
			else
				ind='/';
		}
		if(global_output_style==1)
		{
			if(ind==';')
				printf (";%.1f", timediff_ms(ehip->tp->sent, ehip->tp->recv));
			else
				printf (" timems=\"%.1f", timediff_ms(ehip->tp->sent, ehip->tp->recv));
		}
		else
			printf ("%c%.1f", ind, timediff_ms(ehip->tp->sent, ehip->tp->recv));
    }
}
/*---------------------------------------------------------------------------*/
static void LFTDefaultEventHandler(lft_session_params * sess, int code, const void * params)
{
    const EvtSentPacketParam * spparam;
    const EvtNoReplyParam * nrparam;
    const struct trace_packet_s * packet;
    const EvtDebugCheckpoint1Param * edcpparam;
    const EvtNonSeqPacketParam * enspparam;
    const EvtRecvPacketParam * erpparam;
    const EvtIncomingICMPUDPParam * eiiuparam;
    const EvtIncomingICMPTCPParam * eiitparam;
	const EvtIncomingICMPEchoParam * eiiiparam;
	const EvtIncomingICMPICMPParam * eicmparam;
    const struct tcphdr *tcp;
    const struct udphdr *udp;
	const struct icmp_echo_header_s * echo;
    const struct ip * ip;
	const struct icmp * icmp;

	if(global_output_style==1 && code!=EVT_RPT_PACKET_LIST_END && code!=EVT_RPT_PACKET_INFO)
		printf("<event code=\"%d\"",code);
    switch(code)
    {
	case EVT_AUTOCONFIGURED_TO_PORTS:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" sport=\"%d\" dport=\"%d\" />\n",sess->sport,sess->dport);
			else
				printf ("Autoconfigured to source port %d, destination port %d.\n",sess->sport, sess->dport);
		}
        break;
    case EVT_ADDRESS_INITIALIZED:
		if(global_output_style<2)
		{
			print_host (sess, sess->local_address);
			if(global_output_style==1)
			{
				printf(" protocol=\"%d\"",sess->protocol);
				if(sess->protocol!=2 && sess->protocol!=3)
				{
					if (sess->random_source)
						printf (" rndsport=\"1\" sport=\"%d\"", sess->sport);
					else 
						printf (" rndsport=\"0\" sport=\"%d\"", sess->sport);
				}
				printf(" />\n");
			}
			else
			{
				if(!global_output_style)
				{
					if(sess->protocol==2 || sess->protocol==3)
						printf("\n");
					else
						if (sess->random_source)
							printf (":%d (pseudo-random)\n", sess->sport);
						else 
							printf (":%d\n", sess->sport);
				}
			}
		}
        break;
    case EVT_SENT_PACKET:
        spparam=(const EvtSentPacketParam *)params;
		if(global_output_style==1)
		{
			printf(" protocol=\"%d\" ttl=\"%d\"", sess->protocol, spparam->nhop+1);
			if(!sess->protocol || sess->protocol==4)
			{
				int flcnt=0;
				printf(" seq=\"%u\" xflags=\"%#x\" flags=\"", spparam->tseq, spparam->flags);
				if (spparam->flags & TH_RST)
				{
					printf ("RST");
					flcnt++;
				}
				if (spparam->flags & TH_ACK)
				{
					if(flcnt)
						printf(";");
					printf("ACK");
					flcnt++;
				}
				if (spparam->flags & TH_SYN)
				{
					if(flcnt)
						printf(";");
					printf ("SYN");
					flcnt++;
				}
				if (spparam->flags & TH_FIN)
				{
					if(flcnt)
						printf(";");
					printf ("FIN");
					flcnt++;
				}
				if(!flcnt)
					printf("none");
				printf("\" />\n");
			}
			else if(sess->protocol==1)
			{
				printf(" dport=\"%d\" />\n", (sess->dport + spparam->tttl));
			}
			else
			{
				printf(" />\n");
			}
		}
		else if(!global_output_style)
		{
			if(!sess->protocol || sess->protocol==4)
			{
				printf("SENT TCP  TTL=%d SEQ=%u FLAGS=%#x ( ", spparam->nhop+1, spparam->tseq, spparam->flags);
				if (spparam->flags & TH_RST)
					printf ("RST ");
				if (spparam->flags & TH_ACK)
					printf ("ACK ");
				if (spparam->flags & TH_SYN)
					printf ("SYN ");
				if (spparam->flags & TH_FIN)
					printf ("FIN ");
				printf(")\n");
			}
			else if(sess->protocol==1)
			{
				printf("SENT UDP  TTL=%d DPORT=%d\n", spparam->nhop+1, (sess->dport + spparam->tttl));
			}
			else
			{
				printf("SENT ICMP  TTL=%d\n", spparam->nhop+1);
			}
		}
        break;
    case EVT_SHOW_PAYLOAD:
        packet=(const struct trace_packet_s *)params;
		if(global_output_style==1)
		{
			if(!packet->payload_len)
				printf(" payloadlen=\"%d\" />\n", packet->payload_len);
			else
				printf(" payloadlen=\"%d\">%s</event>\n", packet->payload_len, packet->payload);
		}
		else if(!global_output_style)
		{
			if(!packet->payload_len)
				printf("Payload:  Length=%d  Contents=EMPTY\n", packet->payload_len);
			else
				printf("Payload:  Length=%d  Contents=\"%s\"\n", packet->payload_len, packet->payload);
		}
        break;
    case EVT_SHOW_UDP_CHECKSUM:
        packet=(const struct trace_packet_s *)params;
		if(global_output_style==1)
			printf(" udpsum=\"%#x\"/>\n",packet->udp_hdr.uh_sum);
		else if(!global_output_style)
			printf("UDP Checksum = %#x\n",packet->udp_hdr.uh_sum);
        break;
    case EVT_SHOW_TCP_CHECKSUM:
        packet=(const struct trace_packet_s *)params;
		if(global_output_style==1)
			printf(" tcpsum=\"%#x\"/>\n",packet->tcp_hdr.th_sum);
		else if(!global_output_style)
			printf("TCP Checksum = %#x\n",packet->tcp_hdr.th_sum);
        break;
    case EVT_SHOW_HOPS:
		if(global_output_style==1)
			printf(" uphops=\"%d\" />\n", (int)(*((const short *)params)));
		else if(!global_output_style)
			printf("Upping states of the hops following %d\n", (int)(*((const short *)params)));
        break;
    case EVT_SHOW_NUM_HOPS:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" numhops=\"%d\" />\n", (sess->num_hops+1));
			else
				printf ("Concluding with %d hops.\n", (sess->num_hops+1));
		}
        break;
    case EVT_TRACE_COMPLETED:
		if(global_output_style<2)
		{
			if(global_output_style)
			{
				printf(" />\n");
			}
			else
			{
				if (sess->num_hops && !sess->nostatus && !sess->noisy)
					printf ("T\n");
				else if (!sess->noisy && !sess->nostatus)
					printf ("\n");
			}
		}
        break;
    case EVT_ON_RESOLUTION:
		if(global_output_style<2)
		{
			if(global_output_style)
			{
				printf(" asresolutiontype=\"");
				if(sess->use_radb)
					printf ("RADB");
				else
					if(sess->use_cymru)
						printf ("Cymru");
					else
						if(sess->use_ris)
							printf ("RIPE");
						else
							printf ("PWhoIs");
				printf("\" />\n");
			}
			else
			{
				if(sess->use_radb)
					printf ("Using RADB for in-line AS resolution...\n");
				else
					if(sess->use_cymru)
						printf ("Using Cymru for bulk AS resolution...\n");
					else
						if(sess->use_ris)
							printf ("Using RIPE NCC RIS for bulk AS resolution...\n");
						else
							printf ("Using Prefix WhoIs for bulk AS resolution...\n");
			}
		}
        break;
    case EVT_TRACE_REPORT_START:
		if(global_output_style<2)
		{
			if(!global_output_style)
				printf ("TTL LFT trace to ");
			print_host (sess, sess->remote_address);
			if(global_output_style)
			{
				printf(" protocol=\"%d\"",sess->protocol);
				switch(sess->protocol) 
				{
					case 0:
						printf(" protocolname=\"TCP\" dport=\"%d\" />\n",sess->dport);
						break;
					case 4:
						printf(" protocolname=\"TCP\" dportrange=\"%d-%d\" />\n",sess->dport,(sess->dport + (*((const int *)params))));
						break;
					case 1:
						printf(" protocolname=\"UDP\" dportrange=\"%d-%d\" />\n",sess->dport,(sess->dport + (*((const int *)params))));
						break;
					case 2:
						printf(" protocolname=\"ICMP\" />\n");
						break;
					case 3:
						printf(" protocolname=\"RFC1393\" />\n");
						break;
				}
			}
			else
			{
				switch(sess->protocol) 
				{
					case 0:
						printf(":%d/tcp\n",sess->dport);
						break;
					case 4:
						printf(":%d-%d/tcp\n",sess->dport, (sess->dport + (*((const int *)params))));
						break;
					case 1:
						printf(":%d-%d/udp\n",sess->dport, (sess->dport + (*((const int *)params))));
						break;
					case 2:
						printf("/icmp\n");
						break;
					case 3:
						printf("/rfc1393\n");
						break;
				}
			}
		}
        break;
    case EVT_RPT_NO_REPLY:
		if(global_output_style<2)
		{
			nrparam=(const EvtNoReplyParam *)params;
			if(global_output_style)
			{
				printf(" firstholehop=\"%d\" lastholehop=\"%d\" />\n", nrparam->hopno - nrparam->noreply + 1, nrparam->hopno);
			}
			else
			{
				if (nrparam->noreply == 1)
					printf("**  [neglected] no reply packets received from TTL %d\n", nrparam->hopno);
				if (nrparam->noreply > 1)
					printf("**  [neglected] no reply packets received from TTLs %d through %d\n", nrparam->hopno - nrparam->noreply + 1, nrparam->hopno);
			}
		}
        break;
    case EVT_RPT_FRW_INSPECT_PACKS:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("**  [firewall] the next gateway may statefully inspect packets\n");
		}
        break;
    case EVT_RPT_FRW_STATE_FILTER:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("**  [firewall] the next gateway may implement a flag-based state filter\n");
		}
        break;
    case EVT_RPT_BSD_BUG:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("**  [4.2-3 BSD bug?] the next gateway may errantly reply with reused TTLs\n");
		}
        break;
    case EVT_RPT_PACKET_INFO:
		if(global_output_style<2)
		{
			EvtPacketInfoDefaultHandler(sess, (const EvtPacketInfoParam *)params);
		}
        break;
    case EVT_RPT_PACKET_LIST_END:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf("\" />\n");
			else
				printf ("ms\n");
		}
        break;
    case EVT_RPT_HOP_INFO_START:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf (" index=\"%2d\"", (*((const int *)params)) + 1);
			else
				printf ("%2d ", (*((const int *)params)) + 1);
		}
        break;
    case EVT_RPT_NO_HOPS:
		if(global_output_style<2)
		{
			if(global_output_style)
			{
				printf(" protocol=\"%d\"",sess->protocol);
				if(sess->protocol==0 || sess->protocol==4)
					printf(" protocolname=\"TCP\"");
				else
					if(sess->protocol==1)
						printf(" protocolname=\"UDP\"");
				else
					printf(" protocolname=\"ICMP\"");
				if(sess->target_anomaly)
					printf(" targetanomaly=\"1\"");
				if(sess->target_anomaly || sess->protocol==0)
					printf(" dport=\"%d\"",sess->dport);
				if(!sess->target_anomaly && (sess->protocol==1 || sess->protocol==4))
					printf(" dportrange=\"%d-%d\"",sess->dport,(sess->dport + (*((const int *)params))));
					printf(" />\n");
			}
			else
			{
				if (sess->target_anomaly)
					printf("**  [%d/tcp sequence anomaly from target]  Try advanced options (use -VV to see packets).\n", sess->dport);
				else if (sess->protocol==1)
					printf("**  [%d-%d/udp no reply from target]  Use -VV to see packets.\n", sess->dport, (sess->dport + (*((const int *)params))));
				else if (sess->protocol==0)
					printf("**  [%d/tcp no reply from target]  Try advanced options (use -VV to see packets).\n", sess->dport);
				else if (sess->protocol==4)
					printf("**  [%d-%d/tcp no reply from target]  Use -VV to see packets.\n", sess->dport, (sess->dport + (*((const int *)params))));
				else
					printf("**  [icmp no reply from target]  Try advanced options (use -VV to see packets).\n");
			}
		}
        break;
    case EVT_RPT_TIME_TRACE:
		if(global_output_style<2)
		{
			gettimeofday (&(sess->now), NULL);
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
			if(!sess->UseLocalTime)
				(void)strftime(tbuf, sizeof(tbuf), time_format, (struct tm *) gmtime((time_t *) &(sess->now.tv_sec)));
			else
#endif
			(void)strftime(tbuf, sizeof(tbuf), time_format, (struct tm *)localtime((time_t *) &(sess->now.tv_sec)));
			if(global_output_style)
			{
				printf (" finishtime=\"%s\"", tbuf);
				printf (" elapsed=\"%.2f\"",(timediff_ms(sess->begin_time, sess->now) / 1000));
				printf (" tracingtime=\"%.2f\"", 
						(timediff_ms(sess->begin_time, sess->trace_done_time) / 1000));
				if (sess->resolve_names || sess->do_aslookup || sess->do_netlookup) 
					printf(" resolvingtime=\"%.2f\"", (timediff_ms(sess->trace_done_time, sess->now) / 1000));
				printf(" />\n");
			}
			else
			{
				printf ("LFT trace finished at %s", tbuf);
				printf (" (%.2fs elapsed)",(timediff_ms(sess->begin_time, sess->now) / 1000));
				if (sess->noisy) {
					printf ("\nTime spent tracing: %.2fs", 
							(timediff_ms(sess->begin_time, sess->trace_done_time) / 1000));
					if (sess->resolve_names || sess->do_aslookup || sess->do_netlookup) 
						printf(", resolving: %.2fs", (timediff_ms(sess->trace_done_time, sess->now) / 1000));
				}
				printf("\n");
			}
		}
        break;
    case EVT_ON_EXIT:
		if(global_output_style==1)
			printf(" />\n");
        sess->exit_state=-100;
		if(global_output_style==2)
			GraphVizOutput(sess);
        break;
    case EVT_TTL_NO_REPLY:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" ttl=\"%d\" />\n", (*((const int *)params)));
			else
				printf("No reply on TTL %d\n", (*((const int *)params)));
		}
        break;
    case EVT_PROGRESS_NO_REPLY:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("*");
		}
        break;
	case EVT_PROGRESS_SKIP_PACKET:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("?");
		}
		break;
    case EVT_TTL_TOUT_RESEND:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" ttl=\"%d\" />\n", (*((const int *)params)));
			else
				printf("TTL %d timed out, (resending)\n",(*((const int *)params)));
		}
        break;
    case EVT_TTL_TOUT_GIVINGUP:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" ttl=\"%d\" />\n", (*((const int *)params)));
			else
				printf("TTL %d timed out, (giving up)\n",(*((const int *)params)));
		}
        break;
    case EVT_DBG_CHECKPOINT1:
		if(global_output_style<2)
		{
			edcpparam=(const EvtDebugCheckpoint1Param *)params;
			if(global_output_style)
			{
				printf (" hilength=\"%d\" last_return=\"%d\"", sess->hop_info_length, edcpparam->last_return);
				printf (" no_reply=\"%d\" ahead_limit=\"%d\"", edcpparam->no_reply, sess->ahead_limit);
				printf (" num_hops=\"%d\" need_reply=\"%d\" />\n", sess->num_hops, edcpparam->need_reply);
			}
			else
			{
				printf ("| hilength %d, last_return %d\n", sess->hop_info_length, edcpparam->last_return);
				printf ("| no_reply %d, ahead_limit %d\n", edcpparam->no_reply, sess->ahead_limit);
				printf ("| num_hops %d, need_reply %d\n", sess->num_hops, edcpparam->need_reply);
			}
		}
        break;
    case EVT_CANT_RELIABLY_RTRIP:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("LFT can\'t reliably round-trip.  Close-proximity filter in the way?\n");
		}
        break;
    case EVT_HAVE_UNANSWERRED_HOPS:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("I still have unanswered hops.\n");
		}
        break;
    case EVT_TOO_FAR_AHEAD:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("I\'m too far ahead, returning.\n");
		}
        break;
    case EVT_HAVE_GAPS:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("I know the distance to the target, but I have gaps to fill.  Returning...\n");
		}
        break;
    case EVT_EITHER_RESP_OR_TOUT:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("Everyone either responded or timed out.  ");
		}
        break;
    case EVT_LOOKFOR_UNINC_ACK:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("\nNo match in sequence check, looking for a match inside seq-.\n");
		}
        break;
    case EVT_LOOKFOR_OFF_BY_LEN:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("No match in seq-, looking for a match inside seq+len.\n");
		}
        break;
    case EVT_LOOKFOR_LAST_RESORT:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("No match in seq+len, looking for a match inside last resort loop.\n");
		}
        break;
    case EVT_SKIP_PACKET:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("(packet not meant for us, skip)\n");
		}
        break;
    case EVT_ACK_WAS_NOT_INC:
		if(global_output_style<2)
		{
			enspparam=(const EvtNonSeqPacketParam *)params;
			if(global_output_style)
				printf (" src=\"%s\" pttl=\"%d\" />\n", inet_ntoa (enspparam->ipaddr), enspparam->tp->hopno+1);
			else
			{
				printf ("SRC=%s PTTL=%d\n", inet_ntoa (enspparam->ipaddr), enspparam->tp->hopno+1);
				printf ("Target\'s ACK was not incremented.  ");
			}
		}
        break;
    case EVT_RST_REL_TO_ISN:
		if(global_output_style<2)
		{
			enspparam=(const EvtNonSeqPacketParam *)params;
			if(global_output_style)
			{
				printf (" src=\"%s\" pttl=\"%d\"", inet_ntoa (enspparam->ipaddr), enspparam->tp->hopno+1);
				printf (" payloadlen=\"%d\" />\n", sess->payloadlen);
			}
			else
			{
				printf ("SRC=%s PTTL=%d\n", inet_ntoa (enspparam->ipaddr), enspparam->tp->hopno+1);
				printf ("Target\'s RST relates to the ISN + payload length (%d).  ", sess->payloadlen);
			}
		}
        break;
    case EVT_ACK_WAS_WAY_OFF:
		if(global_output_style<2)
		{
			enspparam=(const EvtNonSeqPacketParam *)params;
			if(global_output_style)
				printf (" src=\"%s\" pttl=\"%d\" />\n", inet_ntoa (enspparam->ipaddr), enspparam->tp->hopno+1);
			else
			{
				printf ("SRC=%s PTTL=%d\n", inet_ntoa (enspparam->ipaddr), enspparam->tp->hopno+1);
				printf ("Target\'s ACK was way off.  ");
			}
		}
        break;
    case EVT_DUPLICATE_PACKET:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf ("(duplicate packet, skip)\n");
		}
        break;
    case EVT_PROGRESS_DUPLICATE:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("!");
		}
        break;
    case EVT_RECV_PACKET:
		if(global_output_style<2)
		{
			erpparam=(const EvtRecvPacketParam *)params;
			if(global_output_style)
				printf (" src=\"%s\" pttl=\"%d\" pseq=\"%u\" />\n", inet_ntoa (erpparam->ipaddr), erpparam->tp->hopno+1, erpparam->seq);
			else
				printf ("SRC=%s PTTL=%d PSEQ=%u\n", inet_ntoa (erpparam->ipaddr), erpparam->tp->hopno+1, erpparam->seq);
		}
        break;
    case EVT_PROGRESS_OK:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf(".");
		}
        break;
    case EVT_TCP_PORT_CLOSED:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf (" dport=\"%d\" />\n", sess->dport);
			else
				printf ("Port %d/tcp appears to be closed; target sent RST.\n", sess->dport);
		}
        break;
    case EVT_TCP_PORT_OPEN:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf (" dport=\"%d\" />\n", sess->dport);
			else
				printf ("Port %d/tcp open; target attempted handshake.\n", sess->dport);
		}
        break;
    case EVT_PROCESS_PACKET_START:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("Received new data from packet capture; processing.\n");
		}
        break;
    case EVT_UDP_NOT_FOR_US:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
			{
				if (sess->noisy>3)
					printf("Not for us\n");
				else
					printf("?");
			}
		}
        break;
	case EVT_INCOMING_ICMP_ICMP:
		if(global_output_style<2)
		{
			eicmparam=(const EvtIncomingICMPICMPParam *)params;
			if(global_output_style)
			{
				printf(" src=\"%s\" proto=\"%d\" ttl=\"%d\"", inet_ntoa(eicmparam->ip->ip_src), eicmparam->ip->ip_p, eicmparam->ip->ip_ttl);
				printf(" protocolname=\"ICMP\"");
				if (eicmparam->icmp->icmp_type == ICMP_TIMXCEED) 
					printf(" icmptype=\"ICMP_TIMXCEED\"");
				else if (eicmparam->icmp->icmp_type == ICMP_UNREACH)
					printf(" icmptype=\"ICMP_UNREACH\"");
				printf(" echoid=\"%d\" echoseq=\"%d\"",(int)eicmparam->echo->id, (int)eicmparam->echo->sequence);
				printf(" />\n");
			}
			else
			{
				printf("INCOMING IP:  SRC=%s PROTO=%d TTL=%d\n", inet_ntoa(eicmparam->ip->ip_src), eicmparam->ip->ip_p, eicmparam->ip->ip_ttl);
				printf("\\->ICMP+ICMP:  ");
				if (eicmparam->icmp->icmp_type == ICMP_TIMXCEED) 
					printf("TTL exceeded; ");
				else if (eicmparam->icmp->icmp_type == ICMP_UNREACH)
					printf("unreachable; ");
				printf("ICMP echo ID=%d SEQ=%d\n",(int)eicmparam->echo->id, (int)eicmparam->echo->sequence);
			}
		}
		break;
	case EVT_INCOMING_ICMP_Echo:
		if(global_output_style<2)
		{
			eiiiparam=(const EvtIncomingICMPEchoParam *)params;
			if(global_output_style)
			{
				printf(" src=\"%s\" proto=\"%d\" ttl=\"%d\"", inet_ntoa(eiiiparam->ip->ip_src), eiiiparam->ip->ip_p, eiiiparam->ip->ip_ttl);
				printf(" protocolname=\"ECHO\" echoid=\"%d\" echoseq=\"%d\"",(int)eiiiparam->echo->id, (int)eiiiparam->echo->sequence);
				printf(" />\n");
			}
			else
			{
				printf("INCOMING IP:  SRC=%s PROTO=%d TTL=%d\n", inet_ntoa(eiiiparam->ip->ip_src), eiiiparam->ip->ip_p, eiiiparam->ip->ip_ttl);
				printf("\\->ICMP+ICMP echo:  ");
				printf("ICMP echo ID=%d SEQ=%d\n",(int)eiiiparam->echo->id, (int)eiiiparam->echo->sequence);
			}
		}
        break;
    case EVT_INCOMING_ICMP_UDP:
		if(global_output_style<2)
		{
			eiiuparam=(const EvtIncomingICMPUDPParam *)params;
			if(global_output_style)
			{
				printf(" src=\"%s\" proto=\"%d\" ttl=\"%d\"", inet_ntoa (eiiuparam->orig_ip->ip_src), eiiuparam->ip->ip_p, eiiuparam->ip->ip_ttl);
				if (eiiuparam->icmp->icmp_type == ICMP_TIMXCEED) 
					printf(" icmptype=\"ICMP_TIMXCEED\"");
				else if (eiiuparam->icmp->icmp_type == ICMP_UNREACH)
					printf(" icmptype=\"ICMP_UNREACH\"");
				printf(" protocolname=\"UDP\" sport=\"%d\" dport=\"%d\"",(ntohs (eiiuparam->udp->uh_sport)), (ntohs (eiiuparam->udp->uh_dport)));
				printf(" />\n");
			}
			else
			{
				printf("INCOMING IP:  SRC=%s PROTO=%d TTL=%d\n", inet_ntoa (eiiuparam->orig_ip->ip_src), eiiuparam->ip->ip_p, eiiuparam->ip->ip_ttl);
				printf("\\->ICMP+UDP:  ");
				if (eiiuparam->icmp->icmp_type == ICMP_TIMXCEED) 
					printf("TTL exceeded; ");
				else if (eiiuparam->icmp->icmp_type == ICMP_UNREACH)
					printf("unreachable; ");
				printf("UDP SPORT=%d DPORT=%d\n", (ntohs (eiiuparam->udp->uh_sport)), (ntohs (eiiuparam->udp->uh_dport)));
			}
		}
        break;
    case EVT_INCOMING_ICMP_TCP:
		if(global_output_style<2)
		{
			eiitparam=(const EvtIncomingICMPTCPParam *)params;
			if(global_output_style)
			{
				printf(" src=\"%s\" proto=\"%d\" ttl=\"%d\"", inet_ntoa (eiitparam->orig_ip->ip_src), eiitparam->ip->ip_p, eiitparam->ip->ip_ttl);
				if (eiitparam->icmp->icmp_type == ICMP_TIMXCEED) 
					printf(" icmptype=\"ICMP_TIMXCEED\"");
				else if (eiitparam->icmp->icmp_type == ICMP_UNREACH)
					printf(" icmptype=\"ICMP_UNREACH\"");
				printf(" protocolname=\"TCP\" sport=\"%d\" dport=\"%d\"",(ntohs (eiitparam->tcp->th_sport)), (ntohs (eiitparam->tcp->th_dport)));
				printf(" />\n");
			}
			else
			{
				printf("INCOMING IP:  SRC=%s PROTO=%d TTL=%d\n", inet_ntoa (eiitparam->orig_ip->ip_src), eiitparam->ip->ip_p, eiitparam->ip->ip_ttl);
				printf("\\->ICMP+TCP:  ");
				if (eiitparam->icmp->icmp_type == ICMP_TIMXCEED) 
					printf("TTL exceeded; ");
				else if (eiitparam->icmp->icmp_type == ICMP_UNREACH)
					printf("unreachable; ");
				printf("TCP SPORT=%d DPORT=%d\n", (ntohs (eiitparam->tcp->th_sport)), (ntohs (eiitparam->tcp->th_dport)));
			}
		}
        break;
	case EVT_RCVD_ICMP_Echo:
		if(global_output_style<2)
		{
			echo=(const struct icmp_echo_header_s *)params;
			if(global_output_style)
				printf(" id=\"%d\" seq=\"%d\" />\n",(int)echo->id, (int)echo->sequence);
			else
				printf("RCVD ICMP echo ID=%d SEQ=%d ",(int)echo->id, (int)echo->sequence);
		}
        break;
	case EVT_RCVD_ICMP_ICMP:
		if(global_output_style<2)
		{
			icmp=(const struct icmp *)params;
			if(global_output_style)
				printf(" icmptype=\"%d\" icmpcode=\"%d\" />\n",(int)icmp->icmp_type,(int)icmp->icmp_code);
			else
				printf("RCVD ICMP type=%d code=%d ",(int)icmp->icmp_type,(int)icmp->icmp_code);
		}
        break;
    case EVT_RCVD_ICMP_UDP:
		if(global_output_style<2)
		{
			udp=(const struct udphdr *)params;
			if(global_output_style)
				printf(" seq=\"%u\" />\n",((ntohs (udp->uh_dport)) - sess->dport));
			else
				printf ("RCVD ICMP SEQ=%u ", ((ntohs (udp->uh_dport)) - sess->dport));
		}
        break;
    case EVT_RCVD_ICMP_TCP:
		if(global_output_style<2)
		{
			tcp=(const struct tcphdr *)params;
			if(global_output_style)
				printf(" seq=\"%u\" />\n",ntohl (tcp->th_seq));
			else
				printf ("RCVD ICMP SEQ=%u ", ntohl (tcp->th_seq));
		}
        break;
    case EVT_RCVD_TCP:
		if(global_output_style<2)
		{
			tcp=(const struct tcphdr *)params;
			if(global_output_style)
			{
				int flcnt=0;
				printf(" xflags=\"%#x\" flags=\"", tcp->th_flags);
				if (tcp->th_flags & TH_RST)
				{
					printf ("RST");
					flcnt++;
				}
				if (tcp->th_flags & TH_ACK)
				{
					if(flcnt)
						printf(";");
					printf("ACK");
					flcnt++;
				}
				if (tcp->th_flags & TH_SYN)
				{
					if(flcnt)
						printf(";");
					printf ("SYN");
					flcnt++;
				}
				if (tcp->th_flags & TH_FIN)
				{
					if(flcnt)
						printf(";");
					printf ("FIN");
					flcnt++;
				}
				if(!flcnt)
					printf("none\"");
				else
					printf("\"");
				printf (" seq=\"%u\" ack=\"%u\"", ntohl (tcp->th_seq), ntohl (tcp->th_ack));
				printf(" />\n");
			}
			else
			{
				printf("RCVD TCP  FLAGS=%#x ( ",tcp->th_flags);
				
				if (tcp->th_flags & TH_SYN)
					printf ("SYN ");
				if (tcp->th_flags & TH_ACK)
					printf ("ACK ");
				if (tcp->th_flags & TH_FIN)
					printf ("FIN ");
				if (tcp->th_flags & TH_RST)
					printf ("RST ");
				
				printf (") SEQ=%u ACK=%u ", ntohl (tcp->th_seq), ntohl (tcp->th_ack));
			}
		}
        break;
    case EVT_RCVD_UNKNOWN:
		if(global_output_style<2)
		{
			ip=(const struct ip *)params;
			if(global_output_style)
			{
				printf(" protocolcode=\"%d\"", ip->ip_p);
#if defined(WIN32) || defined(_WIN32)
				printf(" ipfrom=\"%d.%d.%d.%d\" ipto=\"%d.%d.%d.%d\"", 
					   (int)ip->ip_src.s_net,(int)ip->ip_src.s_host,(int)ip->ip_src.s_lh,(int)ip->ip_src.s_impno,
					   (int)ip->ip_dst.s_net,(int)ip->ip_dst.s_host,(int)ip->ip_dst.s_lh,(int)ip->ip_dst.s_impno);
#endif
				printf(" />\n");
			}
			else
			{
				printf("Incoming datagram contains unsupported protocol %d.\n", ip->ip_p);
#if defined(WIN32) || defined(_WIN32)
				if (sess->noisy > 4)
					printf("\t(from %d.%d.%d.%d to %d.%d.%d.%d)\n", 
						   (int)ip->ip_src.s_net,(int)ip->ip_src.s_host,(int)ip->ip_src.s_lh,(int)ip->ip_src.s_impno,
						   (int)ip->ip_dst.s_net,(int)ip->ip_dst.s_host,(int)ip->ip_dst.s_lh,(int)ip->ip_dst.s_impno);
#endif
			}
		}
        break;
    case EVT_DEVICE_SELECTED:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf (" device=\"%s\" linktype=\"%d\" linktypename=\"%s\" />\n", sess->pcap_dev, sess->pcap_datalink, pcap_datalink_val_to_name(sess->pcap_datalink));
			else 
				printf ("Receiving on %s, transmitting on %s as ", sess->pcap_dev, sess->pcap_send_dev);
		}
        break;
    case EVT_SHOW_INITIAL_SEQNUM:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf (" seqstart=\"%d\" />\n", sess->seq_start);
			else
			{
				printf ("Receive link type is %s (%d), skipping %0d bytes\n", pcap_datalink_val_to_name(sess->pcap_datalink),sess->pcap_datalink,sess->skip_header_len);
				printf ("Transmit Initial Sequence Number (ISN) will be %d\n", sess->seq_start);
			}
		}
        break;
    case EVT_TRACE_START:
		if(global_output_style<2)
		{
			if(global_output_style)
			{
				memset(&tbuf, 0, sizeof(tbuf));
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
				if(!sess->UseLocalTime)
					(void)strftime(tbuf, sizeof(tbuf), time_format, (struct tm *) gmtime((time_t *) &(sess->begin_time.tv_sec)));
				else
#endif
					(void)strftime(tbuf, sizeof(tbuf), time_format, (struct tm *) localtime((time_t *) &(sess->begin_time.tv_sec)));
				printf (" begtime=\"%s\" />\n", tbuf);
			}
			else
			{
				if (sess->timetrace) {
					memset(&tbuf, 0, sizeof(tbuf));
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
					if(!sess->UseLocalTime)
						(void)strftime(tbuf, sizeof(tbuf), time_format, (struct tm *) gmtime((time_t *) &(sess->begin_time.tv_sec)));
					else
#endif
						(void)strftime(tbuf, sizeof(tbuf), time_format, (struct tm *) localtime((time_t *) &(sess->begin_time.tv_sec)));
					printf ("LFT trace started at %s\n", tbuf);
				}
				if (!sess->nostatus && !sess->noisy)
					printf("Tracing ");
			}
		}
        break;
    case EVT_DBG_CHECKPOINT2:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(" />\n");
			else
				printf("Left dispatch.\n");
		}
        break;
    case EVT_DBG_LOG_MESSAGE:
		if(global_output_style<2)
		{
			if(global_output_style)
				printf(">%s</event>\n",(const char *)params);
			else
				printf("%s",(const char *)params);
		}
        break;
	case EVT_OCHECK_START:
		if(global_output_style<2)
		{
			if(global_output_style)
			{
				print_host (sess, sess->remote_address);
				printf(" dport=\"%d\" />\n",sess->dport);
			}
			else
				if(sess->noisy)
				{
					printf("TCP open checking started for ");
					print_host (sess, sess->remote_address);
					printf(" port %d.\n",sess->dport);
				}
		}
        break;
	case EVT_OCHECK_OPEN:
		if(global_output_style<2)
		{
			if(global_output_style)
			{
				print_host (sess, sess->remote_address);
				printf(" dport=\"%d\" />\n",sess->dport);
			}
			else
				if(sess->noisy)
				{
					printf("TCP port %d is open on ",sess->dport);
					print_host (sess, sess->remote_address);
					printf(".\n");
				}
		}
        break;
    }
}
/*---------------------------------------------------------------------------*/
static LFT_CALLBACK LFTErrHandler=LFTDefaultErrorHandler;
static LFT_CALLBACK LFTEvtHandler=LFTDefaultEventHandler;
/*---------------------------------------------------------------------------*/
void LFTInitializeCallbacks(LFT_CALLBACK error_handler, LFT_CALLBACK event_handler)
{
    if(error_handler)
        LFTErrHandler=error_handler;
    else
        LFTErrHandler=LFTDefaultErrorHandler;
    if(event_handler)
        LFTEvtHandler=event_handler;
    else
        LFTEvtHandler=LFTDefaultEventHandler;
}
/*---------------------------------------------------------------------------*/
lft_session_params * LFTSessionOpen(void)
{
    lft_session_params * sess= (lft_session_params *)malloc(sizeof(lft_session_params));
    memset(sess, 0,sizeof(lft_session_params));
    sess->scatter_ms = 20;
    sess->ttl_min = 0;
    sess->hop_info_length = 0;
    sess->hop_info=NULL;
    sess->tcp_flags = TH_SYN;
    sess->use_fins = 0;
    sess->seq_start = 0;       /* generate ISN internally by default */
    sess->dport = 80;          /* set default destination to tcp/80 HTTP */
    sess->sport = 53;          /* set default source to tcp/53 dns-xfer */
    sess->auto_ports = 1;      /* enable port autoselection by default */
    sess->random_source = 0;   /* disable random source port by default */
    sess->set_tos = 0;         /* disable set ToS bit by default */
    sess->userlen = 0;         /* user-requested packet length */
    sess->payloadlen = 0;      /* the final probe payloadlength */
    sess->payload = NULL;
    sess->win_len = 32768;

    sess->timeout_ms = 250;	   /* timeout between retries */
    sess->retry_max = 2;       /* number of retries before giving up */
    sess->retry_min = 1;       /* minimum number of checks per hop */
    sess->ahead_limit = 5;     /* number of probes we can send
                                * without replies if we don't know
                                * the number of hops */
    sess->dflag = 0;

    sess->ttl_limit = 30;      /* max # hops to traverse (highest TTL) */
    sess->break_on_icmp = 1;   /* break on icmp other than time exceeded */
    sess->noisy = 0;           /* disable verbose debug by default */
    sess->nostatus = 0;        /* print status bar by default */
    sess->userdevsel = 0;      /* by default, we'll select the device */
    sess->senddevsel = 0;      /* by default, we won't use a spoof device */
    sess->resolve_names = 1;   /* dns resolution enabled by default */
    sess->hostnames_only = 0;  /* disable printing of IP addresses */
    sess->timetrace = 0;       /* disable tracer timing by default */
    sess->adaptive = 0;		   /* disable state engine by default */
    sess->protocol = 0;         /* use UDP instead of TCP */
    sess->do_netlookup = 0;    /* disable netname lookup by default */
    sess->do_aslookup = 0;     /* disable asn lookup by default */
    sess->use_radb = 0;        /* use RADB instead of pwhois */
    sess->use_cymru = 0;       /* use Cymru instead of pwhois */
    sess->use_ris = 0;         /* use RIPE NCC RIS instead of pwhois */

    sess->num_hops = 0;
    /*sess->num_sent = 0;*/
    sess->num_rcvd = 0;
    sess->target_open = 0;
    sess->target_filtered = 0;
    sess->target_anomaly = 0;

    sess->hostname = NULL;
    sess->hostname_lsrr_size = 0;
    SLIST_INIT(&(sess->trace_packets));
    sess->trace_packets_num = 0;
    sess->pcap_dev = NULL;
    sess->pcap_datalink = -1;
    sess->pcap_send_dev = NULL;
    sess->userdev = NULL;
    sess->senddev = NULL;

    sess->send_sock = 0;

    sess->btcpmap = NULL;
    sess->btcpmapsize = 0;
    sess->btcpdpucnt = 0;
    sess->trg_probe_is_sent = 0;
	
    sess->icmp_packet.packet = NULL;

#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
    sess->recv_sock = 0;
    sess->wsastarted = 0;
#else
    sess->pcapdescr = 0;
#endif
    sess->UseLocalTime=1;
    sess->exit_state=0;
	
	sess->is_graphviz_subquery=0;
	sess->check_seam=0;
	sess->graphviz_icon_path=NULL;
    
    /*sess->wsess=w_init();*/
    return sess;
}
/*---------------------------------------------------------------------------*/
void LFTSessionClose(lft_session_params * sess)
{
    struct trace_packet_info_s 	*tp;
    if(sess->hop_info)
        free(sess->hop_info);
    if(sess->send_sock > 0)
#if defined(WIN32) || defined(_WIN32)
        closesocket(sess->send_sock);
#else
        close(sess->send_sock);
#endif
#if defined(WIN32) || defined(_WIN32)
    if(sess->pcap_dev != NULL)
        free(sess->pcap_dev);
    if(sess->recv_sock > 0)
        closesocket(sess->send_sock);
#else
    if(sess->pcapdescr != 0)
	{
        pcap_close(sess->pcapdescr);
		sess->pcapdescr=0;
	}
#endif
    while(SLIST_FIRST(&(sess->trace_packets)))
    {
        tp=SLIST_FIRST(&(sess->trace_packets));
        SLIST_REMOVE_HEAD(&(sess->trace_packets), next);
        free(tp);
    }
    if(sess->payload)
        free(sess->payload);
	if(sess->icmp_packet.packet)
		free(sess->icmp_packet.packet);
	if(sess->btcpmap)
		free(sess->btcpmap);
    free(sess);
}
/*---------------------------------------------------------------------------*/
/*Use TCP FIN packets exclusively (defaults are SYN)*/
int LFTSetupFIN(lft_session_params * sess)
{
    if (sess->adaptive) {
        LFTErrHandler(sess, WRN_CANT_SETUP_FIN, NULL);
        return 0;
    } 
    sess->tcp_flags = TH_FIN;
    sess->use_fins = 1;
    sess->dport = 25000;
    sess->auto_ports = 0;
    return 1;
}
/*---------------------------------------------------------------------------*/
/*Display hosts symbolically; suppress IP address display*/
int LFTSetupDispSymbHost(lft_session_params * sess)
{
    if(!sess->resolve_names) {
        LFTErrHandler(sess, WRN_CANT_DISP_HOST_NAMES, NULL);
        return 0;
    }
    sess->hostnames_only = 1;
    return 1;
}
/*---------------------------------------------------------------------------*/
int LFTSetupUDPMode(lft_session_params * sess)
{
    int prev_protocol;
    char tmp[30];
    prev_protocol = sess->protocol;
    sess->protocol = 1;
    if(sess->adaptive) {
        LFTErrHandler(sess, WRN_ADAPTIVE_DISABLED_BY_UDP, NULL);
        sess->adaptive = 0;
    }
    if(sess->use_fins) {
        LFTErrHandler(sess, WRN_FIN_DISABLED_BY_UDP, NULL);
        sess->use_fins = 0;
    }
    if(!sess->dflag)
        sess->dport = (start_dport - 1);  
    else
    {
        if(!prev_protocol)
        {
            sprintf(tmp,"%d",sess->dport);
            LFTSetupDestinationPort(sess, tmp);
        }
    }
    sess->auto_ports = 0;
    return 1;
}
/*---------------------------------------------------------------------------*/
int LFTSetupRISLookup(lft_session_params * sess)
{
    int asnlkptp=ASN_LOOKUP_RIS;
    if(sess->use_cymru || sess->use_radb){
        LFTErrHandler(sess, WRN_ONLY_ONE_ASN_LOOKUP, &asnlkptp);
        return 0;
    }
    sess->use_radb = 0;
    sess->use_ris = 1;
    sess->use_cymru = 0;
    sess->do_aslookup = 1;
    return 1;
}
/*---------------------------------------------------------------------------*/
int LFTSetupRADBLookup(lft_session_params * sess)
{
    int asnlkptp=ASN_LOOKUP_RADB;
    if(sess->use_cymru || sess->use_ris){
        LFTErrHandler(sess, WRN_ONLY_ONE_ASN_LOOKUP, &asnlkptp);
        return 0;
    }
    sess->use_radb = 1;
    sess->use_ris = 0;
    sess->use_cymru = 0;
    sess->do_aslookup = 1;
    return 1;
}
/*---------------------------------------------------------------------------*/
int LFTSetupCYMRULookup(lft_session_params * sess)
{
    int asnlkptp=ASN_LOOKUP_CYMRU;
    if(sess->use_radb || sess->use_ris){
        LFTErrHandler(sess, WRN_ONLY_ONE_ASN_LOOKUP, &asnlkptp);
        return 0;
    }
    sess->use_radb = 0;
    sess->use_ris = 0;
    sess->use_cymru = 1;
    sess->do_aslookup = 1;
    return 1;
}
/*---------------------------------------------------------------------------*/
int lft_resolve_port(lft_session_params * sess, const char *strport)
{
	struct addrinfo hint, *ai;
	struct sockaddr_in addr;
	char *end;
	unsigned long port;

	/*
	 * Check if this is numeric, if so simply convert.
	 */
	port = strtoul(strport, &end, 10);
	if (*end == '\0') {
		if (port > 65535) {
			/* XXX Error.  Nothing checks for error, though.  */
			return (-1);
		}
		return (port);
	}

	/*
	 * This is a named service, look it up.
	 */
	memset(&hint, 0, sizeof hint);

	hint.ai_family = AF_INET;

	if (sess->protocol == 1) {
		hint.ai_socktype = SOCK_DGRAM;
		hint.ai_protocol = IPPROTO_UDP; /* UDP */
	} else {
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_protocol = IPPROTO_TCP; /* TCP */
	}

	if (getaddrinfo(NULL, strport, &hint, &ai) != 0) {
		/* XXX Error.  Nothing checks for error, though.  */
		return (-1);
	}

	if (ai->ai_addrlen != sizeof addr) {
		/* XXX Error.  Nothing checks for error, though.  */
		return (-1);
	}

	memcpy(&addr, ai->ai_addr, ai->ai_addrlen);

	return (ntohs(addr.sin_port));
}
/*---------------------------------------------------------------------------*/
int LFTSetupDestinationPort(lft_session_params * sess, char * userport)
{
/*
    char strport[50];
    sprintf(strport,"%u",userport);
*/
    sess->dflag++;
    if(sess->protocol==1)
    { 
	if(lft_resolve_port(sess, userport) > (65535 - sess->ttl_limit))
	{
            sess->dport = (65535 - sess->ttl_limit) - 1;
            LFTErrHandler(sess, WRN_UDP_PORT_TOO_HIGH, &userport);
        }
	else 
            sess->dport = lft_resolve_port(sess, userport) - 1;
    } 
    else
	{
        sess->dport = lft_resolve_port (sess, userport);
    }
    sess->auto_ports = 0;
    return 1;
}
/*---------------------------------------------------------------------------*/
int LFTSetupLengthOfPacket(lft_session_params * sess, int plen)
{
    if(plen > maxpacklen) {
        LFTErrHandler(sess, WRN_PACKET_LENGTH_TOO_HIGH, &plen);
        sess->userlen = maxpacklen;
    } else if(plen < minpacklen) {
        LFTErrHandler(sess, WRN_PACKET_LENGTH_TOO_LOW, &plen);
        sess->userlen = 0;
    } else 
        sess->userlen = plen;
    return 1;
}
/*---------------------------------------------------------------------------*/
int LFTSetupDisableResolver(lft_session_params * sess)
{
    if(!sess->hostnames_only) {
        sess->resolve_names = 0; 
    } else {
        LFTErrHandler(sess, WRN_CANT_DISABLE_RESOLVER, NULL);
    }
    return 1;
}
/*---------------------------------------------------------------------------*/
int LFTSetupSourcePort(lft_session_params * sess, int port)
{
    if(sess->random_source) {
        LFTErrHandler(sess, WRN_ALREADY_RANDOM_SPORT, NULL);

        return 0;
    }
    sess->sport = port;
    return 1;
}
/*---------------------------------------------------------------------------*/
int LFTSetupAdaptiveMode(lft_session_params * sess)
{
    if (sess->protocol==1) {
        LFTErrHandler(sess, WRN_ADAPTIVE_DISABLED_BY_UDP, NULL);
        return 0;
    }                        
    if (sess->use_fins) {
        LFTErrHandler(sess, WRN_ADAPTIVE_DISABLED_BY_FIN, NULL);
        return 0;
    }
    sess->adaptive = 1;
    return 1;
}
/*---------------------------------------------------------------------------*/
int LFTSetupDevice(lft_session_params * sess,char * udev)
{
    if (strlen (udev) > max_net_dev_input) {
        LFTErrHandler(sess, ERR_DEVNAME_TOO_LONG, NULL);
        return 0;
    }
    sess->userdevsel = 1;
    sess->userdev = udev;
    return 1;
}
/*---------------------------------------------------------------------------*/
int LFTSetupSendDevice(lft_session_params * sess,char * sdev)
{
    if (strlen (sdev) > max_net_dev_input) {
        LFTErrHandler(sess, ERR_DEVNAME_TOO_LONG, NULL);
        return 0;
    }
    sess->senddevsel = 1;
    sess->senddev = sdev;
    return 1;
}
/*---------------------------------------------------------------------------*/
int LFTSetupUTCTimes(lft_session_params * sess)
{
#if defined(sun)
    if (putenv("TZ=GMT0") == -1) {
        LFTErrHandler(sess, WRN_UNABLE_SETUP_UTC, NULL);
    }                
#else
#if !defined(WIN32) && !defined(_WIN32)
    if (setenv("TZ", "GMT0", 1) == -1) {
        LFTErrHandler(sess, WRN_UNABLE_SETUP_UTC, NULL);
    }
#endif
#endif
    sess->UseLocalTime=0;
    sess->timetrace = 1;
    return 1;
}
/*---------------------------------------------------------------------------*/
/*                          Refactored part of code                          */
/*---------------------------------------------------------------------------*/
unsigned int new_seq(lft_session_params * sess)
{
    if (sess->adaptive) {
        return rand();
    } else {
        return sess->seq_start + sess->trace_packets_num;
    }
}
/*---------------------------------------------------------------------------*/
#ifndef SCREWED_IP_LEN 
u_int32_t
ip_cksum (const struct ip *ip)
{
    register const u_short *sp = (u_short *) ip;
    register u_int32_t sum = 0; 
    register int count;
    
    /*
     * No need for endian conversions.
     */
    for (count = ip->ip_hl * 2; --count >= 0;)
        sum += *sp++;
    while (sum > 0xffff)
        sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum & 0xffff;
    
    return (sum);
}
#endif
/*---------------------------------------------------------------------------*/
/* A standardized way of calculating checksums */
static unsigned short 
udp_cksum (unsigned short *addr, signed int len) {
    
    unsigned short answer = 0;
    register unsigned short *w = addr;
    register int nleft = len;
    register int sum = 0; 
    
    while(nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    
    if(nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }
    
    sum = (sum>>16) + (sum&0xffff);
    sum += (sum>>16);
    answer = ~sum;
    return (answer);
}
/*---------------------------------------------------------------------------*/
u_int32_t tcp_cksum (struct ip *ip, struct tcphdr *tcp, const char * payload, int payload_len)
{
    u_int32_t sum = 0; 
    register int count;
    u_short *sp;
	u_short *temptcp = (u_short *)malloc(sizeof(struct tcphdr)+payload_len+4);
	u_int32_t tempip;
    
	memset(temptcp, 0,sizeof(struct tcphdr)+payload_len+4);
	memcpy(temptcp, (char *)tcp, sizeof(struct tcphdr));
	memcpy((u_char *)temptcp+sizeof(struct tcphdr),payload,payload_len);
	sp = temptcp;
    for(count = (sizeof(struct tcphdr)+payload_len+(sizeof(struct tcphdr)+payload_len)%2)/2; --count >= 0;)
        sum += *sp++;
	free(temptcp);

	memcpy(&tempip, &ip->ip_src, sizeof ip->ip_src);
	sum += (tempip >> 16) + (tempip & 0xffff);
    
	memcpy(&tempip, &ip->ip_dst, sizeof ip->ip_dst);
	sum += (tempip >> 16) + (tempip & 0xffff);
    
	sum += ip->ip_p << 8;
    
    sum += htons (sizeof (struct tcphdr)+payload_len);
    
    while (sum > 0xffff)
        sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum & 0xffff;
    
    return (sum);
}
/*---------------------------------------------------------------------------*/
static char * 
strtolower (char *input) {
    char *iter = input;
    
    if (input == NULL)
        return NULL;
    
    while (*iter) {
        *iter = tolower (*iter);
        iter++;
    }
    return input;
}
/*---------------------------------------------------------------------------*/
static void
do_auto_ports (lft_session_params * sess, char *hostname, int init_dport)
{
    /*
     *  Provides rudimentary auto-select of source and destination ports
     *  based on parsing the hostname supplied by the user
     *
     *  EXPECTS a string like "mail.example.com" and RETURNS the 
     *  auto-selected src and dst ports if changed or NULL if unchanged
     *
     *  Currently operates on user's input only as a call to
     *  gethostbyaddr() before tracing could slow us down too much
     */
    
    if (strlen(hostname) > 5) {
        
        const char *mailservers[] = { "mail", "smtp", "mx", "relay", "inbound" };
        int cnt = 0;
        hostname = (char *) strtolower(hostname);
        
        for (cnt = 0 ; cnt < 5 ; cnt++)
        {
            if (strstr(hostname,mailservers[cnt]))
            {
                sess->dport = 25;
                sess->sport = 25;
                break;
            }
        }
        
        if (strncmp (hostname,"ftp",3) == 0) {
            sess->dport = 21;
            sess->sport = 19021;
        } else if (strncmp (hostname,"whois",5) == 0) {
            sess->dport = 43;
            sess->sport = 19043;
        } else if (strncmp (hostname,"imap",4) == 0) {
            sess->dport = 143;
            sess->sport = 19143;
        } else if (strncmp (hostname,"pop",3) == 0) {
            sess->dport = 110;
            sess->sport = 19110;
        } else if ((strncmp (hostname,"dns",3) == 0) || (strncmp (hostname,"ns",2) == 0) || (strncmp (hostname,"udns",4) == 0)) {
            sess->dport = 53;
            sess->sport = 53;
        } else if ((strncmp (hostname,"ntp",3) == 0) || (strncmp (hostname,"clock",5) == 0)) {
            sess->dport = 123;
            sess->sport = 123;
        }
        
        if (sess->noisy && (sess->dport != init_dport)) 
            LFTEvtHandler(sess,EVT_AUTOCONFIGURED_TO_PORTS, NULL);
    }
}
/*---------------------------------------------------------------------------*/
unsigned int
get_address(lft_session_params * sess, const char *host)
{
	struct addrinfo hint, *ai;
	struct sockaddr_in addr;

	/*
	 * Check if this is numeric, if so simply convert.
	 */
	if (inet_aton(host, &addr.sin_addr) == 1)
		return (addr.sin_addr.s_addr);

	/*
	 * This is a named host, look it up.
	 */
	memset(&hint, 0, sizeof hint);

	hint.ai_family = AF_INET;

	if (getaddrinfo(host, NULL, &hint, &ai) != 0) {
		LFTErrHandler(sess, ERR_UNKNOWN_HOST, host);
		return (0);
	}

	if (ai->ai_addrlen != sizeof addr) {
		/*
		 * XXX
		 * Is there a better error?
		 */
		LFTErrHandler(sess, ERR_UNKNOWN_HOST, host);
		return (0);
	}

	memcpy(&addr, ai->ai_addr, ai->ai_addrlen);

	return (addr.sin_addr.s_addr);
}
/*---------------------------------------------------------------------------*/
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
/*
 The Windows/Cygwin version of this function uses the winsock built-in 
 WSAIoctl SIO_ROUTING_INTERFACE_QUERY to find the appropriate interface.
 */
static char *
lft_getifforremote(lft_session_params * sess, const char *remote)
{
	struct sockaddr_in in, out;
	unsigned long nBytesReturned;
    
	/* Only do this once of course */
	if (sock < 0) {
		if ((sock = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
            		LFTErrHandler(sess, WRN_GETIFFORREMOTE_SOCKET, NULL);
    			if(sess->wsess != NULL) {
				free(sess->wsess);
				sess->wsess = NULL;
			}
			return NULL;
		}
	}
    
	/* Ask what i/f the packet should go out on */
	in.sin_family = AF_INET;
	in.sin_port = 0;
	in.sin_addr.s_addr = get_address(sess, (char *)remote);
    	if(sess->exit_state < 0){
    		if(sess->wsess != NULL) {
			free(sess->wsess);
			sess->wsess = NULL;
		}
		return NULL;
    	}
	if (SOCKET_ERROR != WSAIoctl(sock, SIO_ROUTING_INTERFACE_QUERY, &in, sizeof(in), &out, sizeof(out), &nBytesReturned, NULL, NULL))
		return lft_getifname(out.sin_addr);
	/* not found */
    	if(sess->wsess != NULL) {
		free(sess->wsess);
		sess->wsess = NULL;
	}
	return NULL;
}
#else
/* 
 The non-Windows version of this function uses connect() to 
 acquire a (UDP) socket to the target and uses the OS's decision 
 as to what interface is appropriate. 
 */
static char *
lft_getifforremote(lft_session_params * sess, const char *remote)
{
    int sd;
    struct sockaddr_in sock;
    uint32_t socklen;
    uint16_t p1;
    
    /* TODO: fill with a better RANDOM */
    
    p1 = rand() % 33525 + 32525;
    
    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        LFTErrHandler(sess, WRN_GETIFFORREMOTE_SOCKET, NULL); 
  	if(sess->wsess != NULL) {
		free(sess->wsess);
		sess->wsess = NULL;
	}
        return NULL;
    }
    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = get_address(sess, remote);
    if(sess->exit_state < 0){
 	if(sess->wsess != NULL) {
		free(sess->wsess);
		sess->wsess = NULL;
	}
        return NULL;
    }
    sock.sin_port = htons(p1);
    if (connect(sd, (const struct sockaddr *)(const void *)&sock, sizeof sock) == -1)
    {
        LFTErrHandler(sess, WRN_GETIFFORREMOTE_CONNECT, NULL);
#if defined(WIN32) || defined(_WIN32)
        closesocket(sd);
#else
        close(sd);
#endif
    	if(sess->wsess != NULL) {
		free(sess->wsess);
		sess->wsess = NULL;
	}
        return NULL;
    }
    
    socklen = sizeof sock;
    if (getsockname(sd, (struct sockaddr *)(void *)&sock, &socklen) == -1) {
        LFTErrHandler(sess, WRN_GETIFFORREMOTE_SOCKNAME, NULL);
#if defined(WIN32) || defined(_WIN32)
        closesocket(sd);
#else
        close(sd);
#endif
    	if(sess->wsess != NULL) {
		free(sess->wsess);
		sess->wsess = NULL;
	}
        return NULL;
    }
    
#if defined(WIN32) || defined(_WIN32)
    closesocket(sd);
#else
    close(sd);
#endif
    
    return lft_getifname(sock.sin_addr);
}
#endif
/*---------------------------------------------------------------------------*/
static void
init_address (lft_session_params * sess, char *remote, const char *pcap_dev)
{

    (void)pcap_dev;
    
    /* this is now set inside device selection routines */
    /* sess->local_address.s_addr = lft_getifaddr (pcap_dev); */	
    
    if (sess->noisy) {
        LFTEvtHandler(sess, EVT_ADDRESS_INITIALIZED, NULL);
        if(sess->exit_state < 0){
        	if(sess->wsess != NULL) {
			free(sess->wsess);
			sess->wsess = NULL;
		}
		return;
	}
    }
    
    sess->remote_address.s_addr = get_address(sess, remote);
}
/*---------------------------------------------------------------------------*/
static void
open_sockets (lft_session_params * sess)
{
	struct timeval tforid;
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
    int optval = 1;
    DWORD dwBytesRet = 2048;
    int rmem = 120832;
    int wmem = 120832;
    BOOL blnFlag=TRUE; 
	int ioctlret;
#endif
#ifdef IP_HDRINCL
    int on = 1;
#endif
    int i;
#if defined(sun) || defined(__CYGWIN__) || defined( WIN32 ) || defined(_WIN32)
    struct sockaddr_in local_bind;
#endif
    
#if defined(sun)
	sess->send_sock = socket (PF_INET, SOCK_RAW, IPPROTO_IP);
#elif defined(BSD_IP_STACK)
	switch(sess->protocol)
	{
	case 0:		/*TCP*/
	case 4:		/*TCP basic*/
		sess->send_sock = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
		break;
	case 1:		/*UDP*/
        sess->send_sock = socket (PF_INET, SOCK_RAW, IPPROTO_UDP);
		break;
	case 2:		/*ICMP basic*/
	case 3:		/*RFC1393*/
		sess->send_sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
		break;
	}
#elif defined(__CYGWIN__) || defined( WIN32 ) || defined(_WIN32)
	switch(sess->protocol)
	{
	case 0:		/*TCP*/
	case 1:		/*UDP*/
	case 4:		/*TCP basic*/
		sess->send_sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
		break;
	case 2:		/*ICMP basic*/
	case 3:		/*RFC1393*/
		sess->send_sock = socket (PF_INET, SOCK_RAW, IPPROTO_ICMP);
		break;
	}
    sess->recv_sock = socket (PF_INET, SOCK_RAW, IPPROTO_IP);

    if (sess->recv_sock < 0) {
        LFTErrHandler(sess, ERR_RAW_SOCKET, NULL);
        return;
    }
    local_bind.sin_addr = sess->local_address;
    local_bind.sin_port = 0;
    local_bind.sin_family = AF_INET;
    if (bind(sess->recv_sock, (const struct sockaddr *)(const void *)&local_bind, sizeof(local_bind)) < 0) {
        LFTErrHandler(sess, ERR_SOCKET_BIND, NULL);
        return;
    }
    /* apparently the cygwin include files don't define this: */
#ifndef SIO_RCVALL
# define SIO_RCVALL 0x98000001
#endif
	ioctlret = WSAIoctl(sess->recv_sock, SIO_RCVALL, &optval, sizeof(optval), NULL, 0, &dwBytesRet, NULL, NULL);
	if (ioctlret < 0)
	{
		LFTErrHandler(sess, WRN_WSAIOCTL, NULL);
		if(sess->exit_state<0)
			return;
	}
#else
	switch(sess->protocol)
	{
	case 0:		/*TCP*/
	case 1:		/*UDP*/
	case 4:		/*TCP basic*/
		sess->send_sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
		break;
	case 2:		/*ICMP basic*/
	case 3:		/*RFC1393*/
		sess->send_sock = socket (PF_INET, SOCK_RAW, IPPROTO_ICMP);
		break;
	}
#endif
    if (sess->send_sock < 0) {
        LFTErrHandler(sess, ERR_RAW_SOCKET, NULL);
	if(sess->wsess) {
		free(sess->wsess);
		sess->wsess = NULL;
	}
        return;
    }
#ifdef IP_HDRINCL
	if (setsockopt (sess->send_sock, IPPROTO_IP, IP_HDRINCL, (char *) &on, sizeof (on)) < 0) {
		LFTErrHandler(sess, ERR_IP_HDRINCL, NULL);
		return;
	}
#endif
#ifdef sun
    local_bind.sin_addr = sess->local_address;
    local_bind.sin_port = 0;
    local_bind.sin_family = AF_INET;
    if (bind (sess->send_sock, (const struct sockaddr *)&local_bind, sizeof (local_bind)) < 0) {
        LFTErrHandler(sess, ERR_SOCKET_BIND, NULL);
        return;
    }
#endif
#ifndef IPDEFTTL
#define IPDEFTTL 200
#endif
	/* if(sess->protocol==4)
	{
		if(sess->userlen == 0)
			sess->userlen=def_payload_len;
		if(!(sess->payload = malloc(sess->userlen)))
		{
			LFTErrHandler(sess, ERR_NOT_ENOUGH_MEM, NULL);
			return;
		}
		memset(sess->payload, 0,sess->userlen);
		sess->trace_packet.payload_len = sess->userlen;      
		sess->payloadlen = sess->trace_packet.payload_len;
		sess->trace_packet.payload = sess->payload;
	}
	else */
    if(sess->protocol==2 || sess->protocol==3)		/*ICMP base or ICMP RFC 1393*/
	{
		u_short ptr2id[sizeof tforid / sizeof (u_short)];
		u_short icmpid=0;
		unsigned int ptridx;
		gettimeofday(&tforid,NULL);
		memcpy(ptr2id, &tforid, sizeof ptr2id);
		for(ptridx=0;ptridx<sizeof(tforid)/sizeof(u_short);ptridx++)
			icmpid^=ptr2id[ptridx];
		generateICMPPacket(sess, 
			LFTErrHandler, 
			LFTEvtHandler, 
			&sess->icmp_packet, 
			1, 
			ptr2id[0],
			1);
	}
	else				/*TCP and UDP*/
	{
		/* Prepare the trace packet (probe) */
		memset (&(sess->trace_packet), 0, sizeof (sess->trace_packet));
	    
		if (sess->userlen == 0 && (sess->protocol==0 || sess->protocol==4)) {
			/* If user doesn't supply length, default to zero-payload for TCP packets */
			sess->trace_packet.payload_len = 0;
			sess->trace_packet.payload = NULL;
		}
		else if (sess->userlen == 0) {
			if(!(sess->payload = malloc(def_payload_len)))
			{
				LFTErrHandler(sess, ERR_NOT_ENOUGH_MEM, NULL);
				return;
			}
			memset(sess->payload, 0, def_payload_len);
			sess->trace_packet.payload_len = def_payload_len;
		} else {
			if (sess->hostname_lsrr_size > 0) {
				if (sess->protocol==1) 
					sess->userlen -= (sizeof (struct ip) + sizeof(struct udphdr) + sess->trace_packet.lsrr.ipl_len + 1);
				else
					sess->userlen -= (sizeof (struct ip) + sizeof(struct tcphdr) + sess->trace_packet.lsrr.ipl_len + 1);
			} else {
				if (sess->protocol==1) 
					sess->userlen -= (sizeof (struct ip) + sizeof(struct udphdr));
				else
					sess->userlen -= (sizeof (struct ip) + sizeof(struct tcphdr));            
			}
			if (!(sess->payload = malloc(sess->userlen+4)))
			{
				LFTErrHandler(sess, ERR_NOT_ENOUGH_MEM, NULL);
				return;
			}
			memset(sess->payload, 0, sess->userlen+4);
			sess->trace_packet.payload_len = sess->userlen;      
		} 
	    
		sess->payloadlen = sess->trace_packet.payload_len;
		sess->trace_packet.payload = sess->payload;
	    
		/* set up initial ip headers, etc. */
	        
		if (sess->hostname_lsrr_size > 0) {
			for (i = 0; i < sess->hostname_lsrr_size; i++) {
				sess->trace_packet.lsrr.data[i] = get_address(sess, sess->hostname_lsrr[i]);
				if(sess->exit_state<0)
				{
					if(sess->payload)
					{
						free(sess->payload);
						sess->payload=NULL;
					}
					return;
				}
			}
			sess->trace_packet.lsrr.ipl_code = IPOPT_LSRR;
			sess->trace_packet.lsrr.ipl_len = sess->hostname_lsrr_size * 4 + 3;
			sess->trace_packet.lsrr.ipl_ptr = 4;
		}
		sess->trace_packet.ip_hdr.ip_v = 4;
		if (sess->hostname_lsrr_size > 0) {
			sess->trace_packet.ip_hdr.ip_hl = 6 + sess->hostname_lsrr_size; /* 5 + 3byte lsrr + addresses + padding */
			if (sess->protocol==1) 
				sess->trace_packet.ip_hdr.ip_len = sizeof (struct ip) + sizeof(struct udphdr) + sess->trace_packet.lsrr.ipl_len + 1 + sess->trace_packet.payload_len;
			else 
				sess->trace_packet.ip_hdr.ip_len = sizeof (struct ip) + sizeof(struct tcphdr) + sess->trace_packet.lsrr.ipl_len + 1 + sess->trace_packet.payload_len;
		} else {
			sess->trace_packet.ip_hdr.ip_hl = 5;
			if (sess->protocol==1) 
				sess->trace_packet.ip_hdr.ip_len = sizeof (struct ip) + sizeof(struct udphdr) + sess->trace_packet.payload_len;
			else
				sess->trace_packet.ip_hdr.ip_len = sizeof (struct ip) + sizeof(struct tcphdr) + sess->trace_packet.payload_len;
		}
		sess->trace_packet.ip_hdr.ip_off = IP_DF;
	    
#ifdef SCREWED_IP_LEN
		/*  trace_packet.ip_hdr.ip_len = sizeof (struct ip) + sizeof(struct tcphdr); */
#else
		sess->trace_packet.ip_hdr.ip_len = htons (sess->trace_packet.ip_hdr.ip_len);
		sess->trace_packet.ip_hdr.ip_off = htons(sess->trace_packet.ip_hdr.ip_off);
#endif
		sess->trace_packet.ip_hdr.ip_ttl = IPDEFTTL;
		if (sess->protocol==1) 
			sess->trace_packet.ip_hdr.ip_p = IPPROTO_UDP;
		else {
			sess->trace_packet.ip_hdr.ip_p = IPPROTO_TCP;
			if (sess->set_tos) 
				sess->trace_packet.ip_hdr.ip_tos = TOSMINDELAY;
			sess->trace_packet.tcp_hdr.th_win = htons (sess->win_len);
			sess->trace_packet.tcp_hdr.th_off = sizeof (struct tcphdr) / 4;
		}
	}
    
    /* 
     * Init hop storage (array)
     * Init global packet info storage (SLIST)
     * Init per-hop packet info storage (SLIST)
     */
    
    sess->hop_info = (struct hop_info_s *)malloc (sizeof(struct hop_info_s) * hop_info_size);
    for (i = 0; i < 256; i++) {
        memset(&(sess->hop_info[i]), 0, sizeof(struct hop_info_s));
        sess->hop_info[i].state = 0;
		sess->hop_info[i].done_packet = NULL;
        SLIST_INIT(&(sess->hop_info[i].packets));
    }
    
    SLIST_INIT(&(sess->trace_packets));
}
/*---------------------------------------------------------------------------*/
static unsigned int
send_packet (lft_session_params * sess, short nhop, unsigned short ttl, unsigned int seq, unsigned char flags)
{
    struct sockaddr_in dest;
    unsigned int tseq=0;
    unsigned short tttl=0;
    struct sumh sum;
    char *buf;
    char *bptr = NULL;
    int blen = 0;
    char *s;
    EvtSentPacketParam espparam;
    
    /* we'll use gettimeofday() from checktimeouts 
     * instead of doing it again here               */
    /* gettimeofday (&now, NULL); */
    
    struct trace_packet_info_s	*pinfo = NULL;
    struct trace_packet_s *packet = NULL;

#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
    buf=(char *)_alloca(maxpacklen+64);
#else
    buf=(char *)alloca(maxpacklen+64);
#endif
    
    if (!(pinfo = (struct trace_packet_info_s *)malloc(sizeof(struct trace_packet_info_s)))) {
        LFTErrHandler(sess, ERR_NOT_ENOUGH_MEM, NULL);
        return 0;
    }
    
    memset(pinfo, 0, sizeof(struct trace_packet_info_s));
    packet = &(pinfo->u.packet);
    memcpy(packet, &(sess->trace_packet), sizeof(struct trace_packet_s));
    
    bptr = buf;
    
    dest.sin_family = AF_INET;
    dest.sin_addr = sess->remote_address;
    dest.sin_port = 0;    
    
    if (seq == 0)
        tseq = new_seq(sess);
    else
        tseq = seq;
    
    if (nhop == -1)
        tttl = ttl;
    else 
        tttl = nhop + 1;
    
    /*There is no place we use this variable*/
    /*sess->num_sent++;*/
    
    sess->ts_last_sent = sess->now;
    
    packet->ip_hdr.ip_ttl = tttl;
    packet->ip_hdr.ip_src = sess->local_address;
    packet->ip_hdr.ip_dst = sess->remote_address;
    
    espparam.flags=flags;
    espparam.nhop=nhop;
    espparam.tseq=tseq;
    espparam.tttl=tttl;
    if (sess->noisy > 1)
    {
        LFTEvtHandler(sess,EVT_SENT_PACKET, &espparam);
        if(sess->exit_state<0)
        {
            free(pinfo);
            return 0;
        }
    }
    
    packet->ip_hdr.ip_sum = 0;
#if !defined(SCREWED_IP_LEN)
    packet->ip_hdr.ip_sum = ip_cksum(&packet->ip_hdr);
#endif
        
    memcpy(bptr, &(packet->ip_hdr), sizeof(struct ip));
    bptr += sizeof(struct ip);
    if (packet->lsrr.ipl_len > 0) {
        memcpy(bptr, &(packet->lsrr), packet->lsrr.ipl_len + 1);
        bptr += (packet->lsrr.ipl_len + 1); /* PADDING !!! */
    }
    
    /* Layer-4 preparation */
    
    if (sess->protocol==1) {
        
        if (sess->noisy > 5) 
        {
            LFTEvtHandler(sess,EVT_SHOW_PAYLOAD, packet);
            if(sess->exit_state<0)
            {
                free(pinfo);
                return 0;
            }
        }
        /* Construct UDP (with payload) */        
        packet->udp_hdr.uh_dport = htons(sess->dport + tttl);
        packet->udp_hdr.uh_sport = htons (sess->sport);
        packet->udp_hdr.uh_ulen = htons ((sizeof (struct udphdr)) + packet->payload_len);
        /* truncated-udplength 0
            packet->udp_hdr.uh_ulen = 0;   
        packet->udp_hdr.th_flags = flags;
        */
                
        /* create pseudo-header for checksum calculation */
        sum.src=sess->local_address.s_addr;
        sum.dst=sess->remote_address.s_addr;
        sum.fill=0;
        sum.protocol=IPPROTO_UDP;
        sum.len=htons(sizeof(struct udphdr) + packet->payload_len);

        if(!( s = (char *)malloc(sizeof(struct sumh)+sizeof(struct udphdr)+packet->payload_len)))
        {
            LFTErrHandler(sess, ERR_NOT_ENOUGH_MEM, NULL);
            free(pinfo);
            return 0;
        }
        memset(s,0,(sizeof(struct sumh)+sizeof(struct udphdr)+packet->payload_len));
        memcpy(s,&sum,sizeof(struct sumh));
        memcpy(s+sizeof(struct sumh),&(packet->udp_hdr),sizeof(struct udphdr));
        memcpy(s+sizeof(struct sumh)+sizeof(struct udphdr),
               packet->payload,packet->payload_len);
        
        packet->udp_hdr.uh_sum=udp_cksum((unsigned short *)(void *)s, 
                                    sizeof(struct sumh)+sizeof(struct udphdr)+packet->payload_len);
        free(s);
        
        if (sess->noisy > 5)
        {
            LFTEvtHandler(sess,EVT_SHOW_UDP_CHECKSUM, packet);
            if(sess->exit_state<0)
            {
                free(pinfo);
                return 0;
            }
        }
        
#if defined(SOLARIS_LENGTH_IN_CHECKSUM)
        packet->udp_hdr.uh_sum = htons (sizeof (struct udphdr) + packet->payload_len);
#endif
        memcpy(bptr, &(packet->udp_hdr), sizeof(struct udphdr));
        bptr += sizeof(packet->udp_hdr);
        memcpy(bptr, packet->payload, packet->payload_len);
        blen = sizeof(struct ip) + packet->lsrr.ipl_len + sizeof(struct udphdr) + packet->payload_len;
    }
    
    else {
        /* Construct TCP (no payload needed) */
        if (sess->noisy > 5) 
        {
            LFTEvtHandler(sess,EVT_SHOW_PAYLOAD, packet);
            if(sess->exit_state<0)
            {
                free(pinfo);
                return 0;
            }
        }
        packet->tcp_hdr.th_dport = htons (sess->dport);
        /*
         trace_packet.tcp_hdr.th_seq = htonl (seq_start + trace_packet_info_length);
         */
        packet->tcp_hdr.th_seq = htonl (tseq);
        packet->tcp_hdr.th_sport = htons (sess->sport);
        packet->tcp_hdr.th_flags = flags;
        
#if defined(SOLARIS_LENGTH_IN_CHECKSUM)
        packet->tcp_hdr.th_sum = htons (sizeof (struct tcphdr)) + packet->payload_len;
#else
        packet->tcp_hdr.th_sum = 0;
        packet->tcp_hdr.th_sum = tcp_cksum(&packet->ip_hdr, &packet->tcp_hdr, packet->payload, packet->payload_len);
#endif
        if (sess->noisy > 5)
        {
            LFTEvtHandler(sess,EVT_SHOW_TCP_CHECKSUM, packet);
            if(sess->exit_state<0)
            {
                free(pinfo);
                return 0;
            }
        }
        
        memcpy(bptr, &(packet->tcp_hdr), sizeof(struct tcphdr));
        bptr += sizeof(packet->tcp_hdr);
        memcpy(bptr, packet->payload, packet->payload_len);
        blen = sizeof(struct ip) + packet->lsrr.ipl_len + sizeof(struct tcphdr) + packet->payload_len;
    }
    
    /* Packet is ready, fire away */
    if (sendto (sess->send_sock, buf, blen, 0, (const struct sockaddr *)(const void *)&dest, sizeof (dest)) < 0) {
        LFTErrHandler(sess, ERR_RAW_TCP_DISABLED, NULL);
        free(pinfo);
        return 0;
    }
    pinfo->hopno = nhop;
    if (sess->protocol==1) 
        pinfo->seq = sess->dport + tttl;
    else if(!sess->protocol)
        pinfo->seq = tseq;
    pinfo->sent = sess->now;
    SLIST_INSERT_HEAD(&(sess->trace_packets), pinfo, next);
    sess->trace_packets_num++;
    
    if (nhop != -1) {
        SLIST_INSERT_HEAD(&(sess->hop_info[nhop].packets), pinfo, next_by_hop);
        sess->hop_info[nhop].num_sent++;
        sess->hop_info[nhop].all_sent++;
        sess->hop_info[nhop].ts_last_sent = sess->now;
    }
    
    return tseq;
}
/*---------------------------------------------------------------------------*/
static unsigned int
send_hop (lft_session_params * sess, short nhop)
{
    WrnBadHopStateParam wbhsp;
    struct hop_info_s *h = &(sess->hop_info[nhop]);
    
    if (!sess->adaptive)
        return send_packet (sess, nhop , 0, 0, sess->tcp_flags);
    
    if (h->state == HS_SEND_FIN) {
        return send_packet(sess, nhop, 0, 0, TH_FIN);
    }
    
    if (h->state == HS_SEND_SYN) {
        return send_packet(sess, nhop, 0, 0, TH_SYN);
    }
    
    if (h->state == HS_SEND_SYN_ACK) {
        return send_packet(sess, nhop, 0, 0, HS_SEND_SYN_ACK);
    }    

    wbhsp.h=h;
    wbhsp.nhop=nhop;
    LFTErrHandler(sess, WRN_BAD_HOP_STATE, &wbhsp);
    return -1;
}
/*---------------------------------------------------------------------------*/
int hop_state_up (lft_session_params * sess, short nhop)
{
    struct hop_info_s *h = &(sess->hop_info[nhop]);
    
    if (h->state == HS_MAX)
        return -1;
    
    /* 1st try FIN, then SYN_ACK, then SYN, then fail (set to MAX) */
    if (h->state == HS_SEND_FIN) 
        h->state = HS_SEND_SYN_ACK;
    else if (h->state == HS_SEND_SYN_ACK)                     
        h->state = HS_SEND_SYN;
    else 
        h->state = HS_MAX;
    
    h->num_sent = 0; /* for this state that is */
    return 0;
}
/*---------------------------------------------------------------------------*/
int hop_state_copy(lft_session_params * sess, short nhop)
{
    int i;
	
    if (sess->noisy > 4)
        LFTEvtHandler(sess,EVT_SHOW_HOPS, &nhop);
    if(sess->exit_state>=0)
    {
        for (i = (nhop+1); i <= 255; i++)
            if (sess->hop_info[i].state < sess->hop_info[nhop].state) {
                sess->hop_info[i].state = sess->hop_info[nhop].state;
                sess->hop_info[i].num_sent = 0;
            }
    }
            
    return 0;
}
/*---------------------------------------------------------------------------*/
static void
finish (lft_session_params * sess)
{
    int hopno;
    int maxhop;
    int reply, noreply;
    int as_for_hop = 0;
    struct trace_packet_info_s 	*tp;
    char *netname; 
	/*int ocres;*/
    char *myApp = (char *)malloc((strlen(version)+1 * sizeof(char)) + (strlen(appname) * sizeof(char)));
    struct ip_list_array *ipaslist = (struct ip_list_array *)malloc(sizeof(struct ip_list_array));
	/* Variables for seam detection */
	int icmpcode;
	int asseam_hopno=-1;
	struct in_addr asseam_hopaddr;
	int netseam_hopno=-1;
	struct in_addr netseam_hopaddr;
	struct in_addr classbmask;
	struct in_addr masked_target;
	int prevasn=-1;
	struct in_addr prevasn_hopaddr;
	int prevasn_hopno;
	int lastishole;
	int netreached=0;
	int isseam;
	/* ---------------------------- */
	inet_aton("255.255.0.0", &classbmask);
	masked_target.s_addr=sess->remote_address.s_addr & classbmask.s_addr;

    EvtPacketInfoParam ehip;
    
    memset(ipaslist, 0, sizeof(struct ip_list_array));
    memset(&tbuf, 0, sizeof(tbuf));
    gettimeofday (&(sess->trace_done_time), NULL);
	/*if(sess->protocol==0)
	{
		ocres = open_check(sess, LFTErrHandler, LFTEvtHandler);
		LFTEvtHandler(sess,EVT_OPEN_CHECK_RESULT,&ocres);
		if(ocres==1)
		{
			sess->target_open=1;
			sess->target_filtered=0;
		}
		else
		{
			sess->target_open=0;
			if(ocres<0)
				sess->target_filtered=0;
			else
				sess->target_filtered=1;
		}
	}*/
    if (sess->noisy > 3)
    {
        LFTEvtHandler(sess, EVT_SHOW_NUM_HOPS, NULL);
        if(sess->exit_state <  0)
        {
	    free(ipaslist);
            free(myApp);
            return;
        }
    }
    if (sess->num_hops) {
        maxhop = sess->num_hops;
        /* display all packets we received from this host */
        SLIST_FOREACH(tp, &(sess->trace_packets), next)
            if (tp->is_done)
                tp->hopno = maxhop;
    } else {
        maxhop = sess->hop_info_length - 1;
    }
    
    LFTEvtHandler(sess, EVT_TRACE_COMPLETED, NULL);
    if(sess->exit_state < 0)
    {
    	free(ipaslist);
        free(myApp);
        return;
    }
    
    /* if user wants ASN resolution from pwhois/cymru/riswhois, do it in bulk */
    if (sess->do_aslookup || sess->do_netlookup) {
        if(sess->noisy > 1)
        {
            LFTEvtHandler(sess,EVT_ON_RESOLUTION, NULL);
            if(sess->exit_state < 0)
            {
	    	free(ipaslist);
                free(myApp);
                return;
            }
        }
        if (!sess->use_radb) {
            /* populate bulk ip_addr_list structure */
            for (hopno = sess->ttl_min; hopno <= maxhop; hopno++) {
                SLIST_FOREACH(tp, &(sess->hop_info[hopno].packets), next_by_hop)  {
                    if (tp->recv.tv_usec) {
                        (*ipaslist).ipaddr[as_for_hop] = tp->hopaddr;
                        as_for_hop++;
                        (*ipaslist).numItems = (as_for_hop);
                        break;
                    }
                }
            }
            if (sess->use_cymru) {         /* use cymru bulk service */
                if (w_lookup_as_cymru_bulk(sess->wsess, &(*ipaslist)) != 0)
                    if (sess->noisy) LFTErrHandler(sess, WRN_NS_LOOKUP_FAILED, NULL);
            } else if (sess->use_ris) {    /* use RIPE NCC RIS service */
                if (w_lookup_all_riswhois_bulk(sess->wsess, &(*ipaslist)) != 0)
                    if (sess->noisy) LFTErrHandler(sess, WRN_NS_LOOKUP_FAILED, NULL);
            } else {                 /* use pwhois bulk service */
                if ((strlen(version) * sizeof(char)) + 1 + (strlen(appname) * sizeof(char)) < 254) {
                    *myApp = '\0';
                    strcat(myApp, appname); 
		    strcat(myApp, " "); 
		    strcat(myApp, version);
                    strncpy((*ipaslist).application,myApp,511);
                }
                if (w_lookup_all_pwhois_bulk(sess->wsess, &(*ipaslist)) != 0)
                    if (sess->noisy)
			LFTErrHandler(sess, WRN_NS_LOOKUP_FAILED, NULL);
            }  
            if(sess->exit_state < 0)
            {
                free(ipaslist);
		free(myApp);
                return;
            }
        }
    } 

	free(myApp);

	if(sess->protocol == 1)
		sess->dport++;
	LFTEvtHandler(sess,EVT_TRACE_REPORT_START, &maxhop);
	if(sess->exit_state < 0){
		free(ipaslist);
		return;
	}

	/* seam detection */
	as_for_hop=0;
	for(hopno = sess->ttl_min; hopno < sess->hop_info_length; hopno++)
	{
		struct in_addr last_hop;
		icmpcode=-100;
		last_hop.s_addr = 0;
		if(sess->hop_info[hopno].all_rcvd)
		{
			lastishole=0;
            SLIST_FOREACH(tp, &(sess->hop_info[hopno].packets), next_by_hop)
			{
                if(tp->recv.tv_sec)
				{
					if(hopno<=maxhop)
						icmpcode=tp->icmp_type;
					if(last_hop.s_addr != tp->hopaddr.s_addr)
					{
						if((tp->hopaddr.s_addr & classbmask.s_addr) == masked_target.s_addr)
							netreached=1;
						else
						{
							netseam_hopno=hopno;
							netseam_hopaddr=tp->hopaddr;
						}
						if(sess->do_aslookup || sess->do_netlookup)
						{
							if (sess->use_radb)
							{ 
								/* using RADB/IRR */
								tp->asnumber = w_lookup_as(sess->wsess, inet_ntoa(tp->hopaddr));
							}
							else
							{
								/* using pwhois by default */
								tp->asnumber = (*ipaslist).asn[as_for_hop];
							}
							if(prevasn==-1)
							{
								if(tp->asnumber)
								{
									prevasn=tp->asnumber;
									prevasn_hopno=hopno;
									prevasn_hopaddr=tp->hopaddr;
								}
							}
							else
							{
								if(tp->asnumber)
								{
									if(tp->asnumber!=prevasn)
									{
										asseam_hopno=prevasn_hopno;
										asseam_hopaddr=prevasn_hopaddr;
									}
									prevasn=tp->asnumber;
									prevasn_hopno=hopno;
									prevasn_hopaddr=tp->hopaddr;
								}
							}
						}
						last_hop=tp->hopaddr;
					}
				}
			}
			as_for_hop++;
		}
		else
			lastishole=1;
		if(icmpcode==-1)
			break;
	}
	if(!netreached)
		netseam_hopno=-1;
	if(lastishole)
		asseam_hopno=-1;
	/* -------------- */
noreply = 0;
reply = 0;
as_for_hop = 0;            /* this correlates the hopno to the asn stored in ipaslist */


for (hopno = sess->ttl_min; hopno <= maxhop; hopno++) {
    struct in_addr last_hop;
    
    if (sess->hop_info[hopno].all_rcvd != 0) {
        if (noreply >= 1)
        {
            EvtNoReplyParam nrp;
            nrp.hopno=hopno;
            nrp.noreply=noreply;
            LFTEvtHandler(sess,EVT_RPT_NO_REPLY, &nrp);
            if(sess->exit_state < 0)
            {
                free(ipaslist);
				return;
			}
        }
    }
    
    last_hop.s_addr = 0;
    if ((sess->hop_info[hopno].state == HS_SEND_FIN) && (sess->hop_info[hopno+1].state == HS_SEND_SYN) && (sess->hop_info[hopno+1].ts_last_recv.tv_sec)) {
        LFTEvtHandler(sess,EVT_RPT_FRW_INSPECT_PACKS, NULL);
        if(sess->exit_state < 0){
        	free(ipaslist);
		return;
	}
    }

    if ((sess->hop_info[hopno].state != HS_SEND_SYN_ACK) && (sess->hop_info[hopno+1].state == HS_SEND_SYN_ACK) && (hopno == (sess->num_hops - 1))) {
        LFTEvtHandler(sess,EVT_RPT_FRW_STATE_FILTER, NULL);
        if(sess->exit_state < 0){
        	free(ipaslist);
		return;
	}
    }    
    
    if ((sess->hop_info[hopno].flags & HF_ENDPOINT) && (noreply >= ((maxhop - sess->ttl_min)/2)) && sess->num_hops > 3) {
        LFTEvtHandler(sess,EVT_RPT_BSD_BUG, NULL);
        if(sess->exit_state < 0){
        	free(ipaslist);
		return;
	}
    }
    
    if (sess->hop_info[hopno].all_rcvd == 0) {
        reply = 0;
    } else {
        LFTEvtHandler(sess,EVT_RPT_HOP_INFO_START,&hopno);
        if(sess->exit_state < 0){
        	free(ipaslist);
		return;
	}

        SLIST_FOREACH(tp, &(sess->hop_info[hopno].packets), next_by_hop) {
            
            if (tp->recv.tv_sec) {
                reply = 1;
                                                                
                if (last_hop.s_addr != tp->hopaddr.s_addr) {
                    ehip.asnumber = 0; 	/* init/clear the ASN */
                    if (sess->do_aslookup) {
                        if (sess->use_radb) { 
                            /* using RADB/IRR */
                            ehip.asnumber = w_lookup_as(sess->wsess, inet_ntoa(tp->hopaddr));
                        } else {
                            /* using pwhois by default */
                            ehip.asnumber = (*ipaslist).asn[as_for_hop];
                        }
                    }
					tp->asnumber=ehip.asnumber;
					ehip.netname=NULL;
                    if (sess->do_netlookup) {
                        if (!sess->do_aslookup || (sess->do_aslookup && !sess->use_cymru && !sess->use_radb)) {
                            netname = (*ipaslist).netName[as_for_hop];
                        } else {
                            netname = w_lookup_netname(sess->wsess, inet_ntoa(tp->hopaddr));
                        }
                        ehip.netname=netname;
                    }
					if(ehip.netname)
						strncpy(tp->netname, ehip.netname, 511);
					else
						tp->netname[0]=0;

                }
                ehip.last_hop=last_hop;
				tp->last_hop=ehip.last_hop;
                last_hop = tp->hopaddr;
            }
            ehip.tp=tp;
			/* seam processing */
			isseam=0;
			ehip.is_asseam=0;
			ehip.is_netseam=0;
			ehip.is_open=0;
			ehip.is_filtered=0;
			ehip.seam_traced=0;
			if(sess->check_seam && hopno==asseam_hopno && tp->hopaddr.s_addr==asseam_hopaddr.s_addr)
			{
				isseam=1;
				ehip.is_asseam=1;
			}
			if(sess->check_seam && hopno==netseam_hopno && tp->hopaddr.s_addr==netseam_hopaddr.s_addr)
			{
				isseam=1;
				ehip.is_netseam=1;
			}
			if(isseam)
			{
				if(sess->check_seam)
				{
					int curroutputstyle=global_output_style;
					char hostname[100];
					ehip.seam_traced=1;
					global_output_style=2;
					lft_session_params * subsess=LFTSessionOpen();
					strncpy(hostname, inet_ntoa(tp->hopaddr),100);
					subsess->senddevsel = sess->senddevsel;
					subsess->senddev = sess->senddev;
					subsess->auto_ports=0;
					subsess->dport=179;
					subsess->seq_start=30;
					subsess->retry_min=1;
					subsess->retry_max=1;
					subsess->resolve_names=0;
					subsess->ahead_limit=1;
					subsess->break_on_icmp = 0;
					subsess->is_graphviz_subquery=1;
					subsess->hostname=hostname;
					subsess->hostname_lsrr_size = 0;
					LFTExecute(subsess);
					ehip.is_open=subsess->target_open;
					ehip.is_filtered=subsess->target_filtered;
					LFTSessionClose(subsess);
					global_output_style=curroutputstyle;
				}
			}
			/* --------------- */
            LFTEvtHandler(sess,EVT_RPT_PACKET_INFO,&ehip);
	    if(sess->exit_state < 0){
            	free(ipaslist);
	    	return;
	    }
        }
        LFTEvtHandler(sess,EVT_RPT_PACKET_LIST_END,NULL);
        if(sess->exit_state < 0){
        	free(ipaslist);
		return;
	}
    }
    if (reply) {
        noreply = 0;
        as_for_hop++;
    } else
        noreply++;
    
    reply = 0;
} /* for(...) */

if (!sess->num_hops){
    LFTEvtHandler(sess, EVT_RPT_NO_HOPS, &maxhop);
}
if (sess->timetrace){
    LFTEvtHandler(sess, EVT_RPT_TIME_TRACE, NULL);
}
LFTEvtHandler(sess, EVT_ON_EXIT, NULL);
free(ipaslist);
return;
}

/*---------------------------------------------------------------------------*/
static int check_timeouts (lft_session_params * sess)
{
    int nhop;
    int need_reply = 0;
    int no_reply = 0;
    int last_return = 0;
    
    gettimeofday (&(sess->now), NULL);
    if (timediff_ms (sess->ts_last_sent, sess->now) < sess->scatter_ms)
        return 0;			/* not ready to send another packet yet */
    
    for (nhop = sess->ttl_min; nhop < sess->hop_info_length; nhop++) {
        if (!sess->hop_info[nhop].num_sent) {
            send_hop(sess, nhop);
            return 0;
        }
    }
    
    for (nhop = sess->ttl_min; nhop < sess->hop_info_length; nhop++) {
        if (sess->hop_info[nhop].num_sent <= sess->retry_max && !sess->hop_info[nhop].ts_last_recv.tv_sec) {
            if (sess->noisy > 4)
            {
                LFTEvtHandler(sess,EVT_TTL_NO_REPLY,&nhop);
                if(sess->exit_state<0)
                    return 0;
            }
            if (timediff_ms (sess->hop_info[nhop].ts_last_sent, sess->now) >= sess->timeout_ms) {
                /* we timed out waiting for this hop -- retry if we have any
                * more tries */
                if (sess->hop_info[nhop].num_sent < sess->retry_max) {
                    if (!sess->noisy && !sess->nostatus)
                        LFTEvtHandler(sess,EVT_PROGRESS_NO_REPLY,NULL);
                    if (sess->noisy > 2)
                        LFTEvtHandler(sess,EVT_TTL_TOUT_RESEND,&nhop);
                    if(sess->exit_state<0)
                        return 0;
                    send_hop(sess, nhop);
                    return 0;
                } else {
                    if (!sess->adaptive || hop_state_up(sess, nhop)) {
                        if (sess->noisy > 3)
                            LFTEvtHandler(sess,EVT_TTL_TOUT_GIVINGUP,&nhop);
                        if(sess->exit_state<0)
                            return 0;
                        no_reply++;
                    }
                }
            } else {
                need_reply++;		/* we have to wait for this one to timeout */
            }
        } else { /* have reply */
            last_return = nhop;
        }
    }
    
    if (sess->noisy > 4) {
        EvtDebugCheckpoint1Param edcp;
        edcp.last_return=last_return;
        edcp.need_reply=need_reply;
        edcp.no_reply=no_reply;
        LFTEvtHandler(sess,EVT_DBG_CHECKPOINT1,&edcp);
        if(sess->exit_state<0)
            return 0;
    }
    if (no_reply >= sess->ahead_limit) {	/* we timed out. */
        if ((last_return + 3) * 2 < sess->hop_info_length) {
            if ((need_reply < 3) && (sess->num_rcvd < 2)) 
                LFTEvtHandler(sess,EVT_CANT_RELIABLY_RTRIP,NULL);
            if(sess->exit_state<0)
                return 0;
            finish (sess);
            return 1;
        }
    }

	if ((!sess->num_hops || sess->hop_info_length < sess->num_hops || need_reply) && sess->hop_info_length < sess->ttl_limit) { 
	    if (sess->noisy > 4) 
	        LFTEvtHandler(sess,EVT_HAVE_UNANSWERRED_HOPS,NULL);
	    if (need_reply >= sess->ahead_limit) {
	        if (sess->noisy > 4)
	            LFTEvtHandler(sess,EVT_TOO_FAR_AHEAD,NULL);
	        return 0;			/* wait for some replies before we go on */
	    }
	    if(sess->exit_state<0)
	        return 0;
    
	    if (sess->num_hops > 0 && sess->hop_info_length >= sess->num_hops) {
	        if (sess->noisy > 3)
	            LFTEvtHandler(sess,EVT_HAVE_GAPS,NULL);
	        return 0;			/* we know how long the path is --
	                             * wait to fill in the blanks      */
	    }
    
	    nhop = sess->hop_info_length++;
	    send_hop(sess, nhop);
	} else
	{ 
	    if (sess->noisy >= 4)
	    {
	        LFTEvtHandler(sess,EVT_EITHER_RESP_OR_TOUT,NULL);
	        if(sess->exit_state<0)
	            return 0;
	    }
	    for (nhop = sess->ttl_min; nhop < sess->hop_info_length; nhop++)
	    {
	        if (sess->hop_info[nhop].num_sent < sess->retry_min && sess->hop_info[nhop].num_sent <= sess->retry_max)
	        {
	            send_hop(sess, nhop);
	            return 0;
	        }
	    }
	    	    
	    /* If we're adaptive and target appears closed, increment state and try again */
	    if ((sess->adaptive) && (sess->target_open < 1) && (sess->hop_info[nhop].state != HS_MAX)) 
	    {
	       hop_state_up(sess, nhop);
	       send_hop(sess, nhop);
	       return 0;
	    }
    
	    finish (sess);
	    return 1;
	}
	return 0;
}
/*---------------------------------------------------------------------------*/
static void
recv_packet (lft_session_params * sess, unsigned int seq, struct in_addr ipaddr, int icmp_type, const struct pcap_pkthdr *hdr)
{
    double ms;
    struct trace_packet_info_s *tp = NULL;
    EvtNonSeqPacketParam ensp;
    
    /* Depending on the platform, we can use
     * the pcap header's timeval or we must call
       gettimeofday() for each packet  */
    
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32) || defined( USE_GTOD )
    (void)hdr;

    gettimeofday (&(sess->now), NULL);
#else
    sess->now.tv_sec = hdr->ts.tv_sec; 
    sess->now.tv_usec = hdr->ts.tv_usec;
    /* gettimeofday (&now, NULL); */
#endif
    
    /* First, search every probe to find an exact sequence match */
    SLIST_FOREACH(tp, &(sess->trace_packets), next) {
        if (tp->seq == seq) {
            break;
        }
    } 

    /* Next, if no probes have an exact sequence match, look for an unincremented ACK */
    if (tp == NULL) {
        if (sess->noisy > 3)
        {
            LFTEvtHandler(sess,EVT_LOOKFOR_UNINC_ACK,NULL);
            if(sess->exit_state<0)
                return;
        }
        SLIST_FOREACH(tp, &(sess->trace_packets), next) {       
            if (((tp->seq) == (seq +1)) && (icmp_type == -1))
                    break;
        }
    }
    
    /* Next, if no probes have an exact sequence match, look for an off-by-len */
    if (tp == NULL) {
        if (sess->noisy > 3)
        {
            LFTEvtHandler(sess,EVT_LOOKFOR_OFF_BY_LEN,NULL);
            if(sess->exit_state<0)
                return;
        }
        SLIST_FOREACH(tp, &(sess->trace_packets), next) {       
            if (((tp->seq) == (seq - sess->payloadlen)) && (icmp_type == -1))
                break;
        }
    }    
    
    /* Last resort.  Catch any response from the target */
    if (tp == NULL) {
        if (sess->noisy > 3)
        {
            LFTEvtHandler(sess,EVT_LOOKFOR_LAST_RESORT,NULL);
            if(sess->exit_state<0)
                return;
        }
        SLIST_FOREACH(tp, &(sess->trace_packets), next) {       
            /* Special case: look for a response to our SYN_ACK */
            if (tp->u.packet.tcp_hdr.th_flags == HS_SEND_SYN_ACK) {
                if (!tp->recv.tv_sec) {
                    break;
                } 
            }            
            /* Truly the last resort: packet from the target with a wacky ACK sequence */
            if ((ipaddr.s_addr == sess->remote_address.s_addr) && (tp->hopaddr.s_addr == 0) && (icmp_type == -1)) {
                sess->target_anomaly = 1;
            }
        }
    }
    
    /* This packet is not even close, drop it and move on */
    if (!tp) {
        if (sess->noisy)
            LFTEvtHandler(sess,EVT_SKIP_PACKET,NULL);
        else
            if (!sess->nostatus) 
				LFTEvtHandler(sess,EVT_PROGRESS_SKIP_PACKET,NULL);
        return;
    }
    
    if (tp->seq != seq) {
        ensp.ipaddr=ipaddr;
        ensp.tp=tp;
        if (((tp->seq) == (seq + 1)) && (icmp_type == -1)) {
            if (sess->noisy > 1) {
                LFTEvtHandler(sess,EVT_ACK_WAS_NOT_INC,&ensp);
                if(sess->exit_state<0)
                    return;
            }
            /* return; */
        } else if (((tp->seq) == (seq - sess->payloadlen)) && (icmp_type == -1)) {
            if (sess->noisy > 1) {
                LFTEvtHandler(sess,EVT_RST_REL_TO_ISN,&ensp);
                if(sess->exit_state<0)
                    return;
            }
            /* return; */
        } else if ((ipaddr.s_addr == sess->remote_address.s_addr) && (icmp_type == -1)) {
            if (sess->noisy > 1) {
                LFTEvtHandler(sess,EVT_ACK_WAS_WAY_OFF,&ensp);
                if(sess->exit_state<0)
                    return;
            }
            /* return; */
        }
    }
    
    if (tp->recv.tv_sec) {
        if (sess->noisy)
            LFTEvtHandler(sess,EVT_DUPLICATE_PACKET, NULL);
        else
            if (!sess->nostatus)
                LFTEvtHandler(sess,EVT_PROGRESS_DUPLICATE,NULL);
        return;
    }
    
    if (sess->noisy > 1) 
    {
        EvtRecvPacketParam erpp;
        erpp.ipaddr=ipaddr;
        erpp.seq=seq;
        erpp.tp=tp;
        LFTEvtHandler(sess,EVT_RECV_PACKET,&erpp);
    }
    else {
        if (!sess->nostatus)
            LFTEvtHandler(sess,EVT_PROGRESS_OK,NULL);
    }
    if(sess->exit_state<0)
        return;
    
    /* increment received packet counter */
    sess->num_rcvd++;
    
    tp->recv = sess->now;
    if (tp->hopno != -1) {
        sess->hop_info[tp->hopno].ts_last_recv = sess->now;
        sess->hop_info[tp->hopno].all_rcvd++;
        hop_state_copy(sess, tp->hopno);
        /* indicate this hop has a sequence anomaly */
        
        if (icmp_type == -1)
            sess->hop_info[tp->hopno].flags |= HF_ENDPOINT;
    }
    
    tp->hopaddr = ipaddr;
    tp->icmp_type = icmp_type;
    if (icmp_type != -2 && (!sess->num_hops || sess->num_hops > tp->hopno))
        if (sess->break_on_icmp || (icmp_type == -1)) {
            if (tp->hopno != -1) { /* we set fake type -1 when we get actual
                * tcp packet in return - meaning destination */
                sess->num_hops = tp->hopno;
                tp->is_done = 1;
                if (sess->noisy > 1 && sess->target_open < 1)
                    LFTEvtHandler(sess,EVT_TCP_PORT_CLOSED,NULL);
                else 
                    if (sess->noisy > 1 && sess->target_open > 0)
                        LFTEvtHandler(sess,EVT_TCP_PORT_OPEN,NULL);
                if(sess->exit_state<0)
                    return;
            }
        }
            
        /* adjust scatter if we have fast reply times */
        ms = timediff_ms (tp->sent, tp->recv);
        sess->scatter_ms = (sess->scatter_ms * (sess->ahead_limit - 1) + ms) / sess->ahead_limit;
    
}
/*---------------------------------------------------------------------------*/
void lft_printf(lft_session_params * sess, const char *templ, ...)
{
  va_list ap;
  char buf[1024];

  va_start (ap, templ);
  vsprintf(buf, templ, ap);
  va_end (ap);
  LFTEvtHandler(sess, EVT_DBG_LOG_MESSAGE, buf);
}
/*---------------------------------------------------------------------------*/
static void process_packet (lft_session_params * sess, const u_char *packet, const struct pcap_pkthdr *hdr)
{
    const struct ether_header *eptr;
    const struct ip *ip, *orig_ip;
    const struct tcphdr *tcp;
    const struct udphdr *udp;
    const struct icmp *icmp;
        
    if (sess->noisy > 4)
    {
        LFTEvtHandler(sess,EVT_PROCESS_PACKET_START,NULL);
        if(sess->exit_state<0)
            return;
    }
    check_timeouts (sess);
    if(sess->exit_state<0) 
        return;
     
    /* Test EtherType to adjust Ethernet header length 
    802.1q VLAN Ethernet frame (dot1q) */
    eptr = (const struct ether_header *) packet;
    if ((sess->skip_header_len == sizeof (struct ether_header)) && (ntohs (eptr->ether_type) == ETHERTYPE_VLAN)) {
        sess->skip_header_len += 4;
    }
        
    packet += sess->skip_header_len;
    ip = (const void *)packet;
            
    packet += 4 * ip->ip_hl;
                
    switch (ip->ip_p) {
        case IPPROTO_ICMP:
            orig_ip = ip;
            icmp = (const void *)packet;
            if (icmp->icmp_type != ICMP_UNREACH && icmp->icmp_type != ICMP_TIMXCEED) {
                return;
            }
                ip = &icmp->icmp_ip;
            if (sess->protocol==1) {
                if (ip->ip_p != IPPROTO_UDP)
                    return;			/* not a response to our udp probe */
            } else {
                if (ip->ip_p != IPPROTO_TCP)
                    return;			/* not a response to our tcp probe */                
            }
            packet = (const u_char *)ip;
            packet += 4 * ip->ip_hl;
            
            if (sess->protocol==1) {
                udp = (const void *)packet;
                if (ntohs (udp->uh_sport) != sess->sport || ip->ip_src.s_addr != sess->local_address.s_addr || ip->ip_dst.s_addr != sess->remote_address.s_addr) {
                    LFTEvtHandler(sess,EVT_UDP_NOT_FOR_US,NULL);
                    return;			/* not for us */      
                }
                if (sess->noisy > 2) {
                    EvtIncomingICMPUDPParam eiiup;
                    eiiup.icmp=icmp;
                    eiiup.ip=ip;
                    eiiup.orig_ip=orig_ip;
                    eiiup.udp=udp;
                    LFTEvtHandler(sess,EVT_INCOMING_ICMP_UDP,&eiiup);
                    if(sess->exit_state<0)
                        return;
                }
                if (sess->noisy > 1)
                {
                    LFTEvtHandler(sess,EVT_RCVD_ICMP_UDP,udp);
                    if(sess->exit_state<0)
                        return;
                }
                recv_packet (sess, ntohs (udp->uh_dport) , orig_ip->ip_src,
                             (icmp->icmp_type == ICMP_TIMXCEED) ? -2 : icmp->icmp_code, hdr);
                if(sess->exit_state<0)
                    return;
            } else {
                tcp = (const void *)packet;
                if (ntohs (tcp->th_dport) != sess->dport || ip->ip_src.s_addr != sess->local_address.s_addr || ip->ip_dst.s_addr != sess->remote_address.s_addr)
                    return;			/* not for us */                
                if (sess->noisy > 2) {
                    EvtIncomingICMPTCPParam eiitp;
                    eiitp.icmp=icmp;
                    eiitp.ip=ip;
                    eiitp.orig_ip=orig_ip;
                    eiitp.tcp=tcp;
                    LFTEvtHandler(sess,EVT_INCOMING_ICMP_TCP,&eiitp);
                    if(sess->exit_state<0)
                        return;
                }
                if (sess->noisy > 1) 
                {
                    LFTEvtHandler(sess,EVT_RCVD_ICMP_TCP,tcp);
                    if(sess->exit_state<0)
                        return;
                }
                recv_packet (sess, ntohl (tcp->th_seq) , orig_ip->ip_src,
                             (icmp->icmp_type == ICMP_TIMXCEED) ? -2 : icmp->icmp_code, hdr);                        
                if(sess->exit_state<0)
                    return;
            }
            return;
            
        case IPPROTO_TCP:
            /* check for RST reply */
            tcp = (const void *)packet;
            if (!(tcp->th_flags & TH_RST) && !(tcp->th_flags & TH_ACK) && !(tcp->th_flags & TH_SYN)) 
                return;			/* not what we're looking for */

            if (ntohs (tcp->th_sport) != sess->dport || ip->ip_src.s_addr != sess->remote_address.s_addr || ip->ip_dst.s_addr != sess->local_address.s_addr) {
                return;			/* not the right connection */
            }
                    
            if (sess->noisy > 1) {
                LFTEvtHandler(sess,EVT_RCVD_TCP,tcp);
                if(sess->exit_state<0)
                    return;
            }
                    
            /*if (ntohl(tcp->th_ack) < seq_start || ntohl(tcp->th_ack) > seq_start + trace_packet_info_length + 1)
            return; * not for us */
                    
            /* Check for SYN,ACK in response to determine if target is listening */
            if ((tcp->th_flags & TH_ACK) && (tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_RST)) 
                sess->target_open++;
            if ((tcp->th_flags & TH_ACK) && !(tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_RST))
                sess->target_open = 0;
                                    
            recv_packet (sess, ntohl (tcp->th_ack) - 1, ip->ip_src, -1, hdr);
            if(sess->exit_state<0)
                return;
             /*Could be nice to host and send a RESET here*/
             /*
             send_packet(-1, IPDEFTTL, ntohl(tcp->th_ack) + 1, TH_RST);
             */
            return;
            
        case IPPROTO_UDP:
            /* could be a probe we sent or something we don't support */
                return;			
            
        default:
            if (sess->noisy > 3)
                LFTEvtHandler(sess,EVT_RCVD_UNKNOWN,ip);
    }
}
/*---------------------------------------------------------------------------*/
#if !defined(__CYGWIN__) && !defined(WIN32) && !defined(_WIN32)
static void
pcap_process_packet (u_char * user_data, const struct pcap_pkthdr *hdr,
                     const u_char * packet)
{
    lft_session_params * sess=(lft_session_params *)(void *)user_data;
	if(sess->exit_state<0)
		return;
    process_packet(sess, packet, hdr);
}
#endif
/*---------------------------------------------------------------------------*/
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
void cygwin_process(lft_session_params * sess)
{
    fd_set fds;
    struct timeval tm;
	int wsaerr;
    tm.tv_sec = 0;
    tm.tv_usec = 100000;

    FD_ZERO(&fds);
    FD_SET(sess->recv_sock, &fds);
    if (select(sess->recv_sock+1, &fds, 0, 0, &tm) < 0) {
		wsaerr=WSAGetLastError();
        LFTErrHandler(sess, ERR_WIN_SELECT, NULL);
        return;
    }
    if (FD_ISSET(sess->recv_sock, &fds)) {
        /* read packet */
        char packetbuf[2048];
        int nread;
        memset(packetbuf, 0, sizeof(packetbuf));
        nread = recv(sess->recv_sock, packetbuf, sizeof(packetbuf), 0);
        if (nread <= 0) {
            LFTErrHandler(sess, ERR_WIN_RECV, NULL);
            return;
        }
        process_packet(sess, packetbuf, NULL);
    }
}

#endif
/*---------------------------------------------------------------------------*/
/*                                  Main of lft                              */
/*---------------------------------------------------------------------------*/
void LFTExecute(lft_session_params * sess)
{
#if !defined(__CYGWIN__) && !defined(WIN32) && !defined(_WIN32)
    char ebuf[PCAP_ERRBUF_SIZE];
    /*static pcap_t *pd;*/
#endif

    sess->exit_state = 0;
    if(sess->auto_ports != 0) 
    {
        do_auto_ports(sess, sess->hostname, sess->dport);
        if(sess->exit_state < 0){
	/* if(sess->hostname != NULL)
		free(sess->hostname); */
	if(sess->wsess != NULL) {
		free(sess->wsess);
		sess->wsess = NULL;
	} 
        return;
	}
    }
    
    if ((sess->do_netlookup != 0) || (sess->do_aslookup != 0))
    {
        sess->wsess = w_init();                                                 /* initialize the whois framework */
        sess->wsess->logprintfCookie = sess; /*Parameter for lft_printf*/
    }
    
    /* if not given network interface, select one automatically */
    if (!sess->userdevsel) {
        sess->pcap_dev = lft_getifforremote(sess, sess->hostname);
        if(sess->exit_state < 0){
            	if(sess->wsess != NULL) {
			free(sess->wsess);
			sess->wsess = NULL;
		}
        	/* if (sess->hostname != NULL)
			free(sess->hostname); */
		return;
	}
#if !defined(__CYGWIN__) && !defined(WIN32) && !defined(_WIN32)
        if (sess->pcap_dev == NULL) 
            sess->pcap_dev = pcap_lookupdev (ebuf);
        if (sess->pcap_dev == NULL) {
            LFTErrHandler(sess, ERR_PCAP_ERROR, ebuf);
	    if(sess->wsess != NULL) {
	    	free(sess->wsess);
		sess->wsess = NULL;
	    }
            /* if (sess->hostname != NULL)
		free(sess->hostname); */
            return;
        }
#else 
        if (sess->pcap_dev == NULL) {
            LFTErrHandler(sess, ERR_DISCOVER_INTERFACE, NULL);
            if(sess->wsess != NULL) {
	    	free(sess->wsess);
		sess->wsess = NULL;
	    }
	     return;
        }
#endif
        /* we have a receive device, set the source address */
        sess->pcap_send_dev = sess->pcap_dev;
        sess->local_address.s_addr = lft_getifaddr(sess->pcap_dev);

    } else {
        struct in_addr addr;
        if (inet_aton(sess->userdev, &addr)) {
            /* specified by ip address -- look up device. */
            sess->pcap_dev = lft_getifname(addr);
            if (sess->pcap_dev != 0) {
                LFTErrHandler(sess, ERR_UNKNOWN_INTERFACE, NULL);
	    	if(sess->wsess != NULL) {
	    		free(sess->wsess);
			sess->wsess = NULL;
		}
                return;
            }
            /* we have a receive device, set the source address */
            sess->local_address.s_addr = lft_getifaddr(sess->pcap_dev);
        } else
            sess->pcap_dev = sess->userdev;
            sess->pcap_send_dev = sess->userdev;
            sess->local_address.s_addr = lft_getifaddr(sess->pcap_dev);
    };
    
    /* if user wants a different/spoof interface, facilitate  */
    if (sess->senddevsel > 0) {
        struct in_addr addr;
        if (inet_aton(sess->senddev, &addr)) {
            /* specified by ip address -- force using default device */
            /*sess->pcap_send_dev = lft_getifname(addr);*/
            sess->pcap_send_dev = lft_getifforremote(sess, sess->hostname);
            if (sess->pcap_send_dev == 0) {
                LFTErrHandler(sess, ERR_UNKNOWN_SEND_INTERFACE, NULL);
                return;
            }
            /* we have a send IP address, set the source address */
            sess->local_address.s_addr = get_address(sess,sess->senddev);
        } else {
            sess->pcap_send_dev = sess->senddev;
            if (sess->pcap_send_dev == 0) {
                LFTErrHandler(sess, ERR_UNKNOWN_SEND_INTERFACE, NULL);
                return;
            }
            /* we have a send device, set the source address */
            sess->local_address.s_addr = lft_getifaddr(sess->pcap_dev);
            }
    };

#if !defined(__CYGWIN__) && !defined(WIN32) && !defined(_WIN32)
    sess->pcapdescr = pcap_open_live (sess->pcap_dev, 1600, 0, 20, ebuf);
    /* retain and inform data link type */
    if (sess->pcapdescr == 0) {
        LFTErrHandler(sess, ERR_PCAP_DEV_UNAVAILABLE, ebuf);
	if(sess->wsess != NULL) {
	    	free(sess->wsess);
		sess->wsess = NULL;
	}
        return;
    }
    sess->pcap_datalink = pcap_datalink(sess->pcapdescr);
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
    sess->skip_header_len = 0;
#else
    /* use pcap datalink type to determine skip_header_len */
    if (sess->pcap_datalink == DLT_RAW)
        sess->skip_header_len = 0;
    else if (sess->pcap_datalink == DLT_PPP)
       sess->skip_header_len += 4;
    else if (sess->pcap_datalink == DLT_PPP_ETHER)
       sess->skip_header_len += (8 + (sizeof (struct ether_header)));
    else if (sess->pcap_datalink == DLT_LINUX_SLL)
       sess->skip_header_len += 16;
    else                             /* assume ethernet: linktype EN10MB */
        sess->skip_header_len = sizeof (struct ether_header);
    /* if we're on what looks like a serial link, up the timeout (scatter will take care of itself) */
    /* if ((sess->pcap_datalink == DLT_PPP || sess->pcap_datalink == DLT_LINUX_SLL) && (sess->timeout_ms == DEFAULT_TIMEOUT_MS))
        sess->timeout_ms += 5000; */
#endif
    if (sess->noisy)
    {
        LFTEvtHandler(sess,EVT_DEVICE_SELECTED,NULL);
        if(sess->exit_state < 0){
        if(sess->wsess != NULL) {
                free(sess->wsess);
		sess->wsess = NULL;
	}
        return;
        }
    }
#ifdef BSD_IP_STACK
#ifndef NETBSD
    uint32_t bpfimmflag = 1;
    /* Instruct device to return packets immediately */
    if (ioctl(pcap_fileno(sess->pcapdescr), BIOCIMMEDIATE, &bpfimmflag) < 0) {
        LFTErrHandler(sess, WRN_BIOCIMMEDIATE, pcap_strerror(errno));
        if(sess->exit_state < 0){
	if(sess->wsess != NULL) {
		free(sess->wsess);
		sess->wsess = NULL;
	}
        if(sess->pcapdescr != 0)
		{
			pcap_close(sess->pcapdescr);
			sess->pcapdescr=0;
		}
        return;
	}
    }
#endif
#endif
    /* Set pcap non-blocking mode */
    if (pcap_setnonblock(sess->pcapdescr, 1, ebuf) < 0) {
        LFTErrHandler(sess, ERR_PCAP_NONBLOCK_ERROR, ebuf);
        if(sess->exit_state < 0){
	if(sess->wsess != NULL) {
	    	free(sess->wsess);
		sess->wsess = NULL;
	}
        /* if(sess->hostname != NULL)
		free(sess->hostname); */
        return;
	}
    }
#endif
    
    if (sess->senddevsel > 0)
      init_address (sess, sess->hostname, sess->pcap_send_dev);
    else
      init_address (sess, sess->hostname, sess->pcap_dev);
    if(sess->exit_state < 0){
	if(sess->wsess != NULL) {
	    	free(sess->wsess);
		sess->wsess = NULL;
	}
        /* if(sess->hostname != NULL)
		free(sess->hostname); */
        return;
    }

    if (!sess->seq_start && sess->protocol != 1) {
        sess->seq_start = rand();
    }

    if (sess->noisy > 3 || (sess->noisy > 0 && sess->seq_start))
    {
        LFTEvtHandler(sess, EVT_SHOW_INITIAL_SEQNUM, NULL);
        if(sess->exit_state < 0){
	if(sess->wsess != NULL) {
	    	free(sess->wsess);
		sess->wsess = NULL;
	}
        /* if (sess->hostname != NULL)
		free(sess->hostname); */
        return;
	}
    }
    
    open_sockets(sess);
    if(sess->exit_state < 0)
    {
        if(sess->send_sock > 0)
        {
#if defined(WIN32) || defined(_WIN32)
            closesocket(sess->send_sock);
#else
            close(sess->send_sock);
#endif
            sess->send_sock = 0;
        }
#if defined(WIN32) || defined(_WIN32)
        if(sess->recv_sock > 0)
        {

            closesocket(sess->recv_sock);
            sess->recv_sock = 0;
        }
#else
    	if(sess->pcapdescr != 0)
		{
        	pcap_close(sess->pcapdescr);
			sess->pcapdescr=0;
		}
#endif
        return;
    }
    
#if !defined(__CYGWIN__) && !defined(WIN32) && !defined(_WIN32)
#ifndef LFT_DONT_USE_SAFE_UID
	if(!sess->check_seam && !sess->is_graphviz_subquery)
		setuid (getuid ());
#endif
#endif
    
    if (sess->adaptive) {
        if (sess->retry_min < 2)
            sess->retry_min = 2;
    }
    
    if (sess->protocol==1) {
        if (sess->retry_min > 2)
            sess->retry_min = 2;
    }

    if (sess->retry_max < sess->retry_min)
        sess->retry_max = sess->retry_min;
    
    gettimeofday (&(sess->begin_time), NULL);
    LFTEvtHandler(sess,EVT_TRACE_START,NULL);
    if(sess->exit_state<0)
    {
        if(sess->send_sock > 0)
        {
#if defined(WIN32) || defined(_WIN32)
            closesocket(sess->send_sock);
#else
            close(sess->send_sock);
#endif
            sess->send_sock = 0;
        }
#if defined(WIN32) || defined(_WIN32)
        if(sess->recv_sock > 0)
        {
            closesocket(sess->recv_sock);
            sess->recv_sock = 0;
        }
#endif
        return;
    }
    if(sess->protocol<2)  /*UDP or TCP*/
	{
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
	    for (;;) {
	        cygwin_process(sess);
	        if(sess->exit_state<0)
	            break;
	        if(check_timeouts(sess))
	            break;
	        if(sess->exit_state<0)
	            break;
	    }
#else
	    while (pcap_dispatch (sess->pcapdescr, -1, pcap_process_packet, (u_char *)sess) >= 0) {
	        if(sess->exit_state<0)
	            break;
	        if (sess->noisy > 6)
	        {
	            LFTEvtHandler(sess,EVT_DBG_CHECKPOINT2,NULL);
	            if(sess->exit_state < 0)
	                break;
	        }
	        if(check_timeouts (sess))
	            break;
	        if(sess->exit_state < 0)
	            break;
	    }
#endif
	}
	else
	{
        if(sess->protocol<4)
            icmp_trace_main_loop(sess, LFTErrHandler, LFTEvtHandler);   /*ICMP traces*/
        else
            tcp_base_trace_main_loop(sess, LFTErrHandler, LFTEvtHandler);
	}
	/*{
		int i;
		printf("\n");
		for(i=0;i<sess->debugmapidx;i++)
		{
			if(sess->debugmap[i].type)
			{
				printf("%3d <<<", i);
				printf("%3d %5d phop=%2d %d.%d.%d.%d\n",
					sess->debugmap[i].hop,
					sess->debugmap[i].port,
					sess->debugmap[i].phop,
					(int)sess->debugmap[i].ip.S_un.S_un_b.s_b1,
					(int)sess->debugmap[i].ip.S_un.S_un_b.s_b2,
					(int)sess->debugmap[i].ip.S_un.S_un_b.s_b3,
					(int)sess->debugmap[i].ip.S_un.S_un_b.s_b4);
			}
			else
			{
				printf("%3d -->", i);
				printf("%3d %5d\n",
					sess->debugmap[i].hop,
					sess->debugmap[i].port);
			}
		}
	}*/
    if(sess->send_sock > 0)
    {  
#if defined(WIN32) || defined(_WIN32)
        closesocket(sess->send_sock);
#else
        close(sess->send_sock);
#endif
        sess->send_sock = 0;
    }
#if defined(WIN32) || defined(_WIN32)
    if(sess->recv_sock > 0)
    {
        closesocket(sess->recv_sock);
        sess->recv_sock = 0;
    }
#endif
}
/*---------------------------------------------------------------------------*/
void setOutputStyle(int nstyle)
{
	if(nstyle<0 || nstyle>2)
		global_output_style=0;
	else
		global_output_style=nstyle;
}

int getOutputStyle(void)
{
	return global_output_style;
}

int outputStyleIsXML(void)
{
	if(global_output_style==1)
		return 1;
	return 0;
}

int outputStyleIsGraphViz(void)
{
	if(global_output_style==2)
		return 1;
	return 0;
}
/*---------------------------------------------------------------------------*/
#define INCSIZE	500
static char * addtostringbuf(char * buf, size_t * bufsz, const char * addstr)
{
	if(!buf || !(*bufsz))
	{
		buf=malloc(INCSIZE);
		*bufsz=INCSIZE;
		buf[0]=0;
	}
	if(strlen(buf)+strlen(addstr)+1>(*bufsz))
	{
		buf=realloc(buf, (*bufsz)+INCSIZE);
		*bufsz+=INCSIZE;
	}
	strncat(buf,addstr,(*bufsz) - strlen(buf) - 1);
	return buf;
}
/*---------------------------------------------------------------------------*/
static char * addNodeToRouteMap(char * routemap, size_t * routemapsz, char * prevlevelnodes, char ** currlevelnodes, size_t * currlevelnodessz, char * node)
{
	char * pnode, * pnodeend;
	char pathbuff[100];
	if((*currlevelnodes) && (*currlevelnodessz))
		*currlevelnodes=addtostringbuf(*currlevelnodes, currlevelnodessz, ";");
	*currlevelnodes=addtostringbuf(*currlevelnodes, currlevelnodessz, node);
	pnode=prevlevelnodes;
	pnodeend=pnode;
	while(pnodeend)
	{
		pnodeend=strchr(pnode,';');
		if(pnodeend)
			*pnodeend=0;
		snprintf(pathbuff,100,"\t%s -> %s;\n",pnode,node);
		routemap=addtostringbuf(routemap, routemapsz, pathbuff);
		if(pnodeend)
		{
			*pnodeend=';';
			pnode=pnodeend+1;
		}
	}
	return routemap;
}
/*---------------------------------------------------------------------------*/
static void UpdateLatency(const struct trace_packet_info_s 	*tp, double * minlat, double * maxlat, int * latinitialized)
{
    double currlat=timediff_ms(tp->sent, tp->recv);
	if(!(*latinitialized))
	{
		*minlat=currlat;
		*maxlat=currlat;
		*latinitialized=1;
	}
	else
	{
		if(*minlat > currlat)
			*minlat=currlat;
		if(*maxlat < currlat)
			*maxlat=currlat;
	}
}
/*---------------------------------------------------------------------------*/
static void PrintPacketInfoForGraphViz(lft_session_params * sess, const struct trace_packet_info_s 	*tp)
{
    if(tp->recv.tv_sec)
	{
        if (tp->last_hop.s_addr != tp->hopaddr.s_addr)
		{
            if (sess->do_aslookup)
			{
				if (tp->asnumber)
					printf(" [%d]", tp->asnumber);
				else
					printf(" [AS?]");
            }
            if (sess->do_netlookup)
			{
				if(tp->netname && strlen(tp->netname)>0)
					printf(" [%s]", tp->netname);
				else
					printf(" [Net?]");
            }
            if (tp->icmp_type < -2 || tp->icmp_type > 17)
				printf (" [icmp code %d]", tp->icmp_type);
            else 
			{
                if (tp->icmp_type >= 0)
					printf (" [%s]", icmp_messages[tp->icmp_type + 1]);
			}
			
			printf(" ");
            print_host (sess, tp->hopaddr);
            if (tp->icmp_type == -1 && (sess->protocol<2 || sess->protocol>3))
				printf(":%d",sess->dport);
        }
    }
}
/*---------------------------------------------------------------------------*/
void GraphVizOutput(lft_session_params * sess)
{
	int reply,noreply,neglstart,neglend,anomtype,hopno,maxhop,icmpcode,holecount=0;
	char * rankstring=NULL;
	size_t rankstringsz=0;
    struct trace_packet_info_s 	*tp;
	char netnamecopy[512];
	char * prevlevelnodes=NULL;
	size_t prevlevelnodessz=0;
	char * currlevelnodes=NULL;
	size_t currlevelnodessz=0;
	char * routemap=NULL;
	size_t routemapsz;
	char nodenamebuff[200];
	double minlat, maxlat;
	char latencybuf[100];
	int latinitialized;
	int asseam_hopno=-1;
	struct in_addr asseam_hopaddr;
	int netseam_hopno=-1;
	struct in_addr netseam_hopaddr;
	struct in_addr classbmask;
	struct in_addr masked_target;
	int prevasn=-1;
	struct in_addr prevasn_hopaddr;
	int prevasn_hopno;
	int lastishole;
	int netreached=0;
	int isseam;
	char cpath[1024];
	int lastpos;
		
	if(sess->is_graphviz_subquery)
		return;
	
	if(sess->graphviz_icon_path)
		strncpy(cpath,sess->graphviz_icon_path,1022);
	else
	{
		if(!getcwd(cpath,1022))
		{
			cpath[0]='.';
			cpath[1]=DIRECTORY_SPLITTER;
			cpath[2]=0;
		}
	}
	lastpos=strlen(cpath)-1;
	if(cpath[lastpos]!=DIRECTORY_SPLITTER)
	{
		cpath[lastpos+1]=DIRECTORY_SPLITTER;
		cpath[lastpos+2]=0;
	}
	
	inet_aton("255.255.0.0", &classbmask);
	masked_target.s_addr=sess->remote_address.s_addr & classbmask.s_addr;

	printf("digraph %s {\n",GVGRAPHNAME);
	printf("\trankdir=TB;\n\tnode [fontname=%s,fontsize=%s];\n",GVFONTNAME,GVFONTSIZE);
	printf("\tSRC[%s, label=<",GVHOPSTYLE_SOURCE);
	prevlevelnodes=addtostringbuf(prevlevelnodes, &prevlevelnodessz, "SRC");
	rankstring=addtostringbuf(rankstring, &rankstringsz, "Source");
	printf("%s%s%s%s",GVNTBEG,cpath,GVNIMG_SOURCE,GVNTMID);
	print_host (sess, sess->local_address);
	if(sess->protocol==2 || sess->protocol==3)
		printf("%s>];\n",GVNTEND);
	else
	{
		if (sess->random_source)
			printf (":%d (pseudo-random)%s>];\n", sess->sport, GVNTEND);
		else 
			printf (":%d%s>];\n", sess->sport, GVNTEND);
	}
    if (sess->num_hops)
        maxhop = sess->num_hops;
    else
        maxhop = sess->hop_info_length - 1;
    noreply = 0;
    reply = 0;
	neglstart=-1;
	neglend=-1;
	/* Find SEAMs at first*/
	for(hopno = sess->ttl_min; hopno < sess->hop_info_length; hopno++)
	{
		icmpcode=-100;
		if(sess->hop_info[hopno].all_rcvd)
		{
			lastishole=0;
            SLIST_FOREACH(tp, &(sess->hop_info[hopno].packets), next_by_hop)
			{
                if(tp->recv.tv_sec)
				{
					if(hopno<=maxhop)
						icmpcode=tp->icmp_type;
					if(tp->last_hop.s_addr != tp->hopaddr.s_addr)
					{
						if((tp->hopaddr.s_addr & classbmask.s_addr) == masked_target.s_addr)
							netreached=1;
						else
						{
							netseam_hopno=hopno;
							netseam_hopaddr=tp->hopaddr;
						}
						if(sess->do_aslookup || sess->do_netlookup)
						{
							if(prevasn==-1)
							{
								if(tp->asnumber)
								{
									prevasn=tp->asnumber;
									prevasn_hopno=hopno;
									prevasn_hopaddr=tp->hopaddr;
								}
							}
							else
							{
								if(tp->asnumber)
								{
									if(tp->asnumber!=prevasn)
									{
										asseam_hopno=prevasn_hopno;
										asseam_hopaddr=prevasn_hopaddr;
									}
									prevasn=tp->asnumber;
									prevasn_hopno=hopno;
									prevasn_hopaddr=tp->hopaddr;
								}
							}
						}
					}
				}
			}
		}
		else
			lastishole=1;
		if(icmpcode==-1)
			break;
	}
	if(!netreached)
		netseam_hopno=-1;
	if(lastishole)
		asseam_hopno=-1;
	for(hopno = sess->ttl_min; hopno < sess->hop_info_length; hopno++)
	{
		icmpcode=-100;
		latinitialized=0;
		anomtype=0;
        if((sess->hop_info[hopno].state == HS_SEND_FIN) && (sess->hop_info[hopno+1].state == HS_SEND_SYN) && (sess->hop_info[hopno+1].ts_last_recv.tv_sec))
			anomtype=1;
        if((sess->hop_info[hopno].state != HS_SEND_SYN_ACK) && (sess->hop_info[hopno+1].state == HS_SEND_SYN_ACK) && (hopno == (sess->num_hops - 1)))
			anomtype=2;
        if((sess->hop_info[hopno].flags & HF_ENDPOINT) && (noreply >= ((maxhop - sess->ttl_min)/2)) && sess->num_hops > 3)
			anomtype=3;
        if(sess->hop_info[hopno].all_rcvd == 0)
		{
			reply=0;
			if(neglstart==-1)
				neglstart=hopno;
			neglend=hopno;
		}
		else
		{
			if(neglstart!=-1)
			{
				holecount++;
				printf("\tHOLE%d[%s, label=<",holecount,GVHOPSTYLE_HOLE);
				printf("%s%s%s%s",GVNTBEG,cpath,GVNIMG_HOLE,GVNTMID);
				snprintf(nodenamebuff,200,"HOLE%d",holecount);
				printf("Potentially Cloaked Device%s>];\n",GVNTEND);
				routemap=addNodeToRouteMap(routemap, &routemapsz, prevlevelnodes, &currlevelnodes, &currlevelnodessz, nodenamebuff);
				free(prevlevelnodes);
				prevlevelnodes=currlevelnodes;
				prevlevelnodessz=currlevelnodessz;
				currlevelnodes=NULL;
				currlevelnodessz=0;
				if(neglstart == neglend)
					snprintf(nodenamebuff,200,"\"No reply received from TTL %d\"", neglstart+1);
				else
					snprintf(nodenamebuff,200,"\"No reply received from TTLs %d through %d\"", neglstart+1, neglend+1);
				rankstring=addtostringbuf(rankstring, &rankstringsz, " -> ");
				rankstring=addtostringbuf(rankstring, &rankstringsz, nodenamebuff);
				neglstart=-1;
				neglend=-1;
			}
			int cnt=0;
            SLIST_FOREACH(tp, &(sess->hop_info[hopno].packets), next_by_hop)
            {
                if(tp->recv.tv_sec)
                {
					const char * img=GVNIMG_REGULAR;
					cnt++;
					if(hopno<=maxhop)
						icmpcode=tp->icmp_type;
                    reply = 1;
					strncpy(netnamecopy, tp->netname, 511);
					if(tp->last_hop.s_addr != tp->hopaddr.s_addr)
					{
						if(icmpcode==-1)
						{
							printf("\tTRG[");
							snprintf(nodenamebuff,200,"TRG");

							if(sess->target_open > 0)
							{
								printf("%s, label=<%s%s", GVHOPSTYLE_TARGET_OPEN,GVNTBEG,cpath);
								img=GVNIMG_TRGOPEN;
							}
							else
							{
								if(sess->target_filtered)
								{
									printf("%s, label=<%s%s", GVHOPSTYLE_TARGET_FILTERED,GVNTBEG,cpath);
									img=GVNIMG_TRGFILTERED;
								}
								else
								{
									printf("%s, label=<%s%s", GVHOPSTYLE_TARGET_CLOSED, GVNTBEG, cpath);
									img=GVNIMG_TRGCLOSED;
								}
							}
						}
						else
						{
							printf("\tHOP%d_%d[",hopno+1,cnt);
							snprintf(nodenamebuff,200,"HOP%d_%d",hopno+1,cnt);
							switch (anomtype)
							{
								case 1:
									printf("%s, label=<%s%s", GVHOPSTYLE_ANOMALY1, GVNTBEG, cpath);
									img=GVNIMG_ANOMALY1;
									break;
								case 2:
									printf("%s, label=<%s%s", GVHOPSTYLE_ANOMALY2, GVNTBEG, cpath);
									img=GVNIMG_ANOMALY2;
									break;
								case 3:
									printf("%s, label=<%s%s", GVHOPSTYLE_ANOMALY3, GVNTBEG, cpath);
									img=GVNIMG_ANOMALY3;
									break;
								default:
									printf("%s, label=<%s%s", GVHOPSTYLE_BASE, GVNTBEG, cpath);
									img=GVNIMG_REGULAR;
									break;
							}
						}
						if(img==GVNIMG_REGULAR && ((hopno==asseam_hopno && tp->hopaddr.s_addr==asseam_hopaddr.s_addr) || (hopno==netseam_hopno && tp->hopaddr.s_addr==netseam_hopaddr.s_addr)))
							img=GVNIMG_SEAM;
						routemap=addNodeToRouteMap(routemap, &routemapsz, prevlevelnodes, &currlevelnodes, &currlevelnodessz, nodenamebuff);
						UpdateLatency(tp,&minlat,&maxlat,&latinitialized);
						printf("%s%s",img,GVNTMID);
						PrintPacketInfoForGraphViz(sess,tp);
						isseam=0;
						if(hopno==asseam_hopno && tp->hopaddr.s_addr==asseam_hopaddr.s_addr)
						{
							printf("</td></tr><tr><td>(AS-Method Seam");
							isseam=1;
						}
						if(hopno==netseam_hopno && tp->hopaddr.s_addr==netseam_hopaddr.s_addr)
						{
							printf("</td></tr><tr><td>(Network-Method Seam");
							isseam=1;
						}
						if(isseam)
						{
							if(sess->check_seam)
							{
								printf(": ");
								char hostname[100];
								lft_session_params * subsess=LFTSessionOpen();
								strncpy(hostname, inet_ntoa(tp->hopaddr),100);
								subsess->senddevsel = 1;
								subsess->senddev = sess->pcap_send_dev;
								subsess->userdevsel = 1;
								subsess->userdev = sess->pcap_dev;
								subsess->auto_ports=0;
								subsess->dport=179;
								subsess->seq_start=30;
								subsess->retry_min=1;
								subsess->retry_max=1;
								subsess->resolve_names=0;
								subsess->ahead_limit=1;
								subsess->break_on_icmp = 0;
								subsess->is_graphviz_subquery=1;
								subsess->hostname=hostname;
								subsess->hostname_lsrr_size = 0;
								LFTExecute(subsess);
								if(subsess->target_open > 0)
									printf("Vulnerable/Handshake");
								else
								{
									if(subsess->target_filtered)
										printf("Protected/Filtered");
									else
										printf("Vulnerable/Shun");
								}
								LFTSessionClose(subsess);
							}
							printf(")");
						}
						printf("%s>];\n",GVNTEND);
					}
					else
						UpdateLatency(tp,&minlat,&maxlat,&latinitialized);
                }
            }
			if(minlat==maxlat)
				snprintf(latencybuf,100,": %.1fms",minlat);
			else
				snprintf(latencybuf,100,": %.1f - %.1fms",minlat,maxlat);
			if(icmpcode==-1)
			{
				rankstring=addtostringbuf(rankstring, &rankstringsz, " -> \"Destination");
				if (sess->protocol==0 || sess->protocol==4)
				{
					rankstring=addtostringbuf(rankstring, &rankstringsz, " [target ");
					if (sess->target_open > 0)
						rankstring=addtostringbuf(rankstring, &rankstringsz, "open]");
					else
					{
						if(sess->target_filtered > 0)
							rankstring=addtostringbuf(rankstring, &rankstringsz, "filtered]");
						else
							rankstring=addtostringbuf(rankstring, &rankstringsz, "closed]");
					}
				}
				rankstring=addtostringbuf(rankstring, &rankstringsz, latencybuf);
			}
			else
			{
				snprintf(nodenamebuff,200,"\"%d", hopno+1);
				rankstring=addtostringbuf(rankstring, &rankstringsz, " -> ");
				rankstring=addtostringbuf(rankstring, &rankstringsz, nodenamebuff);
				rankstring=addtostringbuf(rankstring, &rankstringsz, latencybuf);
			}
			switch (anomtype)
			{
				case 1:
					rankstring=addtostringbuf(rankstring, &rankstringsz, "\\n");
					rankstring=addtostringbuf(rankstring, &rankstringsz, GV_ANOMALY1_TEXT);
					break;
				case 2:
					rankstring=addtostringbuf(rankstring, &rankstringsz, "\\n");
					rankstring=addtostringbuf(rankstring, &rankstringsz, GV_ANOMALY2_TEXT);
					break;
				case 3:
					rankstring=addtostringbuf(rankstring, &rankstringsz, "\\n");
					rankstring=addtostringbuf(rankstring, &rankstringsz, GV_ANOMALY3_TEXT);
					break;
				default:
					break;
			}
			rankstring=addtostringbuf(rankstring, &rankstringsz, "\"");

			free(prevlevelnodes);
			prevlevelnodes=currlevelnodes;
			prevlevelnodessz=currlevelnodessz;
			currlevelnodes=NULL;
			currlevelnodessz=0;
		}
		if(icmpcode==-1)
			break;
	}
	if(neglstart!=-1)
	{
		holecount++;
		printf("\tHOLE%d[%s, label=<",holecount,GVHOPSTYLE_HOLE);
		printf("%s%s%s%s",GVNTBEG,cpath,GVNIMG_HOLE,GVNTMID);
		snprintf(nodenamebuff,200,"HOLE%d",holecount);
		printf("No Response%s>];\n",GVNTEND);
		routemap=addNodeToRouteMap(routemap, &routemapsz, prevlevelnodes, &currlevelnodes, &currlevelnodessz, nodenamebuff);
		free(prevlevelnodes);
		prevlevelnodes=currlevelnodes;
		prevlevelnodessz=currlevelnodessz;
		currlevelnodes=NULL;
		currlevelnodessz=0;
		snprintf(nodenamebuff,200,"\"No reply received after TTL %d\"", neglstart+1);
		rankstring=addtostringbuf(rankstring, &rankstringsz, " -> ");
		rankstring=addtostringbuf(rankstring, &rankstringsz, nodenamebuff);
		neglstart=-1;
		neglend=-1;
	}
	free(prevlevelnodes);
	printf("\tranksep=equally;\n\t{\n\t\tnode [shape=plaintext];\n\t\t%s;\n\t}\n",rankstring);
	free(rankstring);
	printf("%s",routemap);
	free(routemap);
	printf("}\n");
}
/*---------------------------------------------------------------------------*/
