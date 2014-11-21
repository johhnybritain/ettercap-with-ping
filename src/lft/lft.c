/*
 
 This file is part of LFT.
 
 The LFT software provided in this Distribution is
 Copyright 2007 VOSTROM Holdings, Inc.
 
 The full text of our legal notices is contained in the file called
 COPYING, included with this Distribution.
 
 Authors:
 
 -  Victor Oppleman <lft@oppleman.com>
 -  Eugene Antsilevitch <ugen@xonix.com>
 
 Other copyrights and former authors:
 
 -  Portions copyright (c) Genuity, Inc. 
 -  Portions copyright (c) Markus Gothe <nietzsche@lysator.liu.se>
 -  Portions copyright (c) Nils McCarthy
 
 */
#include "lft_lib.h"

/* BEGIN Added by Roy T. to improve DNS speed/reliability */
#include <resolv.h>
extern struct __res_state _res;
/* END Added by Roy T. to improve DNS speed/reliability */

#if 0
static char def_payload[] = "\0\0\0\0\0\0\0\0\0\0"; /* default payload for UDP packets */
#endif

const char *version = "3.73";  		/* set version string */
static const char *version_date = "(08/2014)";	/* date of this version */

static void
usage(lft_session_params * sess, char *prog)
{
    fprintf (stderr,
             "\nLayer Four Traceroute (LFT)\n\n"
             "    - the alternative traceroute tool for network [reverse] engineers\n"
             "                                          visit http://www.pwhois.org\n\n"
             "Usage: %s [<options>] [<gateway> <...>] <target:port>\n"
             "\nMainstream Options:\n"
             "  -s <sport>       Source port number\n"
             "  -d <dport>       Destination port number (same as using target:port as target)\n"
             "  -z               Pseudo-randomize the source port number\n"
             "  -m <min>         Minimum number of probes to send per hop\n"
             "  -M <max>         Maximum number of probes to send per hop\n"
             "  -D <device|ip>   Listen-on/use a device by name or address (\"en1\" or \"1.2.3.4\")\n"
             "  -L <length>      Set the length of the probe packet in bytes\n"
             "\nAdvanced Tracing Options:\n"
             "  -F               Use TCP FIN packets exclusively (defaults are SYN)\n"
             "  -f <device|ip>   Send using a device by name or address (spoofing allowed)\n"
             "  -e | -E          Use LFT's stateful engine to detect firewalls and path anomalies\n"
             "  -u               Use traditional UDP (probes) for tracing instead of TCP\n"
             "  -b               Basic TCP trace\n"
             "  -p               Use traditional ICMP (probes) for tracing instead of TCP\n"
             /*"  -P               Use RFC1393 IP option for tracing instead of TCP\n" */
             "  -a <ahead>       Number of hops forward to query before pausing to wait for replies\n"
             "  -c <scatter ms>  Minimum number of milliseconds between subsequent probes\n"
             "  -t <timeout ms>  Maximum RTT to wait before assuming packet was dropped\n"
             "  -l <min ttl>     Minimum TTL to use on outgoing packets (skips close-proximity hops)\n"
             "  -H <ttl>         Maximum number of hops to traverse (max TTL of packets)\n"
             "  -q <sequence>    Set the initial sequence number (ISN) manually\n"
             "  -I               Set the ToS field in the IP packet to minimize-delay\n"
             "  -i               Disable \"stop on ICMP\" other than TTL expired\n"
             "\nResolution Options:\n"
             "  -n               Display hosts numerically; disable use of the DNS resolver\n"
             "  -h               Display hosts symbolically; suppress IP address display\n"
             "  -N               Display network or AS names where appropriate\n"
             "  -A               Display AS numbers resolved by Prefix WhoIs\n"
             "\nAdvanced Resolution Options:\n"
             "  -r               Use RIPE NCC's RIS to resolve ASNs instead of Prefix WhoIs\n"
             "  -R               Use the RADB to resolve ASNs instead of Prefix WhoIs\n"
             "  -C               Use Cymru to resolve ASNs instead of Prefix WhoIs\n"
             "\nVerbosity Options and Status:\n"
             "  -T               Use execution timers and summarize where LFT spent its time\n"
             "  -U               Display all times in UTC (GMT0).  Activates -T option automatically\n"
             "  -S               Disable the status bar (only show the completed trace)\n"
             "  -V               Display verbose/debug output.  Use more \'V\'s for additional detail\n"
             "  -x               XML output\n"  
             "  -g               GraphViz output\n"  
             "  -G <icons path>  Enable GraphViz output and override path to icons\n"
             "  -y               Test destination upstream transition hop\n"
             "  -v               Display LFT's version information and exit\n"  
             "\n"
             "Default is: %s -s %d -d %d -m %d -M %d -a %d -c %.0f -t %d -H %d \n\n",
             prog, prog, sess->sport, sess->dport, sess->retry_min, sess->retry_max, sess->ahead_limit,
             sess->scatter_ms, sess->timeout_ms, sess->ttl_limit);
   exit(EXIT_FAILURE);
}

static void
show_version (void)
{
    fprintf (stderr, "\n"
             "Layer Four Traceroute (LFT) - version %s %s\n\n    - the alternative traceroute tool for network [reverse] engineers\n\n"
             "    Compile-time options:\n\n"
#if defined(DARWIN)
             "      + Darwin (or MacOS)\n"
#endif
#if defined(UNIVERSAL)
             "      + Universal binary\n"
#endif
#if defined(NETBSD)
             "      + NetBSD\n"
#endif
#if defined(OPENBSD)
             "      + OpenBSD\n"
#endif
#if defined(BSD_IP_STACK)
             "      + BSD IP stack\n"
#endif
#if defined(BSD)
             "      + BSD platform\n"
#endif
#if defined(linux)
             "      + Linux platform\n"
#endif
#if defined(sun)
             "      + SUN platform\n"
#endif
#if !defined(sun) && !defined(linux) && !defined(BSD_IP_STACK) && !defined(OPENBSD)
             "      (unknown architecture)\n"
#endif
#if defined(SCREWED_IP_LEN)
             "      + IP length big-endian\n"
#else
             "      + IP length little-endian\n"
#endif
#if defined(IP_HDRINCL)
             "      + Full IP headers for raw sockets\n"
#else
             "      + Without IP header inclusion\n"
#endif
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32) || defined( USE_GTOD )
             "      + Calling gettimeofday() on each packet\n"
#endif
             "      + " HOST_SYSTEM_TYPE "\n"
             "\n", version, version_date);
    exit(EXIT_SUCCESS);
}

extern int
main (int argc, char **argv)
{
    lft_session_params * sess;
    int ch;
    char *cp = NULL;
    struct timeval tb;
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
    WORD wVersionRequested;
    WSADATA wsaData;
    wVersionRequested = MAKEWORD( 2, 2 );
    WSAStartup( wVersionRequested, &wsaData );
#endif

    /* BEGIN Added by Roy T. to improve DNS speed/reliability */
    res_init();
    _res.retrans = 1;
    _res.retry = 1;
    /* END Added by Roy T. to improve DNS speed/reliability */

    sess = LFTSessionOpen();
    setbuf(stdout, NULL);
    
    while ((ch = getopt(argc, argv, "Aa:bCc:D:d:EeFf:H:hIiL:l:M:m:NnPpq:RrSs:Tt:UuVvxw:zgG:y")) != EOF)
        switch (ch) {
            case 'f':
                LFTSetupSendDevice(sess, optarg);
                break;
            case 'F':
                LFTSetupFIN(sess);
                break;
            case 'h':
                LFTSetupDispSymbHost(sess);
                break;
            case 'u':
                LFTSetupUDPMode(sess);
                break;
            case 'r':
                LFTSetupRISLookup(sess);
                break;
            case 'R':
                LFTSetupRADBLookup(sess);
                break;
            case 'C':
                LFTSetupCYMRULookup(sess);
                break;
            case 'd':
                LFTSetupDestinationPort(sess, optarg);
                break;
            case 'L':
                LFTSetupLengthOfPacket(sess, (int)strtol(optarg, (char **)NULL, 10));
                break;                
            case 'q':
                sess->seq_start = strtol(optarg, (char **)NULL, 10);
                break;
            case 'w':
                sess->win_len = (int)strtol(optarg, (char **)NULL, 10);
                break;
            case 'm':
                sess->retry_min = (int)strtol(optarg, (char **)NULL, 10);
                break;
            case 'M':
                sess->retry_max = (int)strtol(optarg, (char **)NULL, 10);
                break;
            case 'N':
                sess->do_netlookup = 1;
                break;
            case 'A':
                sess->do_aslookup = 1;
                break;
            case 'n':
                LFTSetupDisableResolver(sess);
                break;
            case 'T':
                sess->timetrace = 1;
                break;
            case 's':
                LFTSetupSourcePort(sess, lft_resolve_port(sess,optarg));
                break;
            case 'E':
            case 'e':
                LFTSetupAdaptiveMode(sess);
                break;
            case 'S':
                sess->nostatus = 1;
                break;
            case 'D':
                LFTSetupDevice(sess,optarg);
                break;
            case 'a':
                sess->ahead_limit = (int)strtol(optarg, (char **)NULL, 10);
                break;
            case 'c':
                sess->scatter_ms = (int)strtol(optarg, (char **)NULL, 10);
                if (sess->scatter_ms < 1)
                    sess->scatter_ms = 1;
                    if (sess->scatter_ms > 100)
                        sess->scatter_ms = 100;
                        break;
            case 't':
                sess->timeout_ms = (int)strtol(optarg, (char **)NULL, 10);
                break;
            case 'p':
		sess->protocol = 2;
                break;
            /*case 'P':					//We comment this option. Hardly any routers support this.
		sess->protocol = 3;
                break;*/
            case 'b':
		sess->protocol = 4;
                break;
            case 'H':
                if (strtol(optarg, (char **)NULL, 10) > 255) 
                    sess->ttl_limit = 255; else
                        sess->ttl_limit = (int)strtol(optarg, (char **)NULL, 10);
                break;
            case 'l':
                sess->ttl_min = (int)strtol(optarg, (char **)NULL, 10);
                sess->hop_info_length = sess->ttl_min;
                if (sess->ttl_min > 0)
                    sess->ttl_min--;
                    break;
            case 'i':
                sess->break_on_icmp = 0;
                break;
            case 'I':
                sess->set_tos = 1;
                break;
            case 'v':
                show_version();
                break;
            case 'U':   /* show all times in UTC */
                LFTSetupUTCTimes(sess);
                break;                
            case 'V':
                sess->noisy++;
                sess->nostatus = 1; 
                break;
            case 'z':
                sess->random_source = 1;
                /* Yes, this is a ridiculous randomizer, but it's adequate */
                sess->sport = rand()%32525+32525;
                break;
            case 'x':
                setOutputStyle(1);
                break;
            case 'g':
                setOutputStyle(2);
                break;
            case 'G':
                setOutputStyle(2);
				sess->graphviz_icon_path=optarg;
                break;
            case 'y':
                sess->check_seam=1;
                break;
            default:
                usage(sess, argv[0]);
        }
            
    if((argc - optind) < 1)
	usage(sess, argv[0]);
        
    if (sess->noisy && !outputStyleIsXML() && !outputStyleIsGraphViz())
        printf ("Layer Four Traceroute (LFT) version %s", version);
    if (sess->noisy > 1 && !outputStyleIsXML() && !outputStyleIsGraphViz()) 
        printf (" ... (verbosity level %d)",sess->noisy);
    if (sess->noisy && !outputStyleIsXML() && !outputStyleIsGraphViz())    
        printf ("\n");
	if(outputStyleIsXML())
	{
		printf("<lft verbositylevel=\"%d\">\n",sess->noisy);
	}
    gettimeofday (&tb, NULL);
    /* eventually this might want to use /dev/urandom or
        * something on machines that have it.  otherwise,
        * this does a fairly decent job of using the system
        * clock.
        *
        * multiply tv_usec (range 0-1000000) to be in range 0-2^31,
        * and xor to randomize the high bits of tv_sec that don't
        * change very much.
        */
    srand(tb.tv_sec ^ (tb.tv_usec * 2147));
    
    sess->hostname = argv[optind++];
    sess->hostname_lsrr_size = 0;
    while (optind < argc) {
        sess->hostname_lsrr[sess->hostname_lsrr_size++] = argv[optind++];
        if (sess->hostname_lsrr_size > IP_LSRR_DEST) {
			if(outputStyleIsXML())
			{
				printf("<error>Unknown host: Too many LSRR hosts - maximum is 8</error>");
				printf("</lft>\n");
			}
			else
			{
				fprintf(stderr, "LFT: Too many LSRR hosts - maximum is 8\n");
			}
            exit(EXIT_FAILURE);
        }
    }
    if (sess->hostname_lsrr_size > 0) {
        sess->hostname_lsrr[sess->hostname_lsrr_size++] = sess->hostname;
        sess->hostname = sess->hostname_lsrr[0];
    }
    
    /* allow hostname:port if -d not specified and not using UDP */
    if ((cp = strchr(sess->hostname, ':'))) {
        if (!sess->dflag) {
            *cp++ = '\0';
            sess->dport = lft_resolve_port (sess,cp);
            if (sess->protocol==1) {
                sess->dport = (lft_resolve_port (sess,cp)) - 1;
                if (sess->dport > (65535 - sess->ttl_limit)) {
                    sess->dport = (65535 - sess->ttl_limit) - 1;
					if(outputStyleIsXML())
						printf("<warning>Starting UDP port %d is too high.  Will start with %d instead.</warning>",sess->dport, (65535 - sess->ttl_limit));
					else
					{
						fprintf (stderr,
								 "LFT warning: Starting UDP port %d is too high.  Will start with %d instead.\n", sess->dport, (65535 - sess->ttl_limit));
					}
                }
            }
            sess->auto_ports = 0;
        }
    }
    LFTExecute(sess);

    LFTSessionClose(sess);
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
    WSACleanup();
#endif
	if(outputStyleIsXML())
		printf("</lft>\n");
	//getch();
    return 0;
}
