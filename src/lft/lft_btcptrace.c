#include "lft_btcptrace.h"

#include "lft_lib.h"

static LFT_CALLBACK LFTErrHandler=0;
static LFT_CALLBACK LFTEvtHandler=0;

static int getFreePort(lft_session_params * sess, int startfrom)
{
	int i;
	if(sess->btcpmap == NULL)
	{
		if(!(sess->btcpmap = malloc(sizeof(BasicTCPMapEntry) * (sess->ttl_limit * sess->retry_max + 1))))
		{
			LFTErrHandler(sess, ERR_NOT_ENOUGH_MEM, NULL);
			return 0;
		}
		sess->btcpmapsize=sess->ttl_limit * sess->retry_max + 1;
		for(i=0;i<sess->btcpmapsize;i++)
		{
			sess->btcpmap[i].nhop = -1;
			sess->btcpmap[i].port = sess->dport + i;
			sess->btcpmap[i].sentcount=0;
		}
		sess->latestmapchoice=0;
		/*sess->debugmapidx=0;*/
	}
	for(i=(startfrom && sess->latestmapchoice>=startfrom)?sess->latestmapchoice+1:startfrom;i<sess->btcpmapsize;i++)
	{
		if(sess->btcpmap[i].nhop==-1)
		{
			if(startfrom)
				sess->latestmapchoice=i;
			return sess->btcpmap[i].port;
		}
	}
	return sess->dport;
}

static int probeIsSent(lft_session_params * sess, int port, int nhop)
{
	int i = port - sess->dport;
	if(i<0 || i>=sess->btcpmapsize)
	{
		LFTErrHandler(sess, ERR_BTCP_WRONG_PORT_VALUE, NULL);
		return 0;
	}
	if(sess->btcpmap[i].nhop!=-1 && sess->btcpmap[i].nhop!=nhop)
	{
		LFTErrHandler(sess, ERR_BTCP_PROBE_PORT_IS_BUSY, NULL);
		return 0;
	}
	sess->btcpmap[i].nhop=nhop;
	sess->btcpmap[i].sentcount++;
	return sess->btcpmap[i].sentcount;
}

static int probeIsRecvd(lft_session_params * sess, int port)
{
	int nhop;
	int i = port - sess->dport;
	if(i<0 || i>=sess->btcpmapsize)
	{
		LFTErrHandler(sess, ERR_BTCP_WRONG_PORT_VALUE, NULL);
		return 0;
	}
	nhop=sess->btcpmap[i].nhop;
	sess->btcpmap[i].sentcount--;
	if(sess->btcpmap[i].sentcount<1)
	{
		sess->btcpmap[i].nhop=-1;
		sess->btcpmap[i].sentcount=0;
	}
	return nhop;
}

#if 0
static int hopByPort(lft_session_params * sess, int port)
{
	int nhop;
	int i = port - sess->dport;
	if(i<0 || i>=sess->btcpmapsize)
		return -1;
	nhop=sess->btcpmap[i].nhop;
	if(sess->btcpmap[i].port != port || sess->btcpmap[i].sentcount<1)
		return -1;
	return nhop;
}
#endif

static unsigned int tcp_base_send_hop(lft_session_params * sess, short nhop, int searchfrom)
{
    struct sockaddr_in dest;
    unsigned int tseq=0;
    unsigned short tttl=0;
    char * buf;
    char* bptr = NULL;
    int blen = 0;
	int port;
    EvtSentPacketParam espparam;
    
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
	port=getFreePort(sess, searchfrom);
    dest.sin_port = htons(port);    
    
	tseq = new_seq(sess);
    
	tttl = nhop + 1;
    
    sess->ts_last_sent = sess->now;
    
    packet->ip_hdr.ip_ttl = tttl;
    packet->ip_hdr.ip_src = sess->local_address;
    packet->ip_hdr.ip_dst = sess->remote_address;
    
    espparam.flags=sess->tcp_flags;
	if(sess->adaptive)
	{
		struct hop_info_s *h = &(sess->hop_info[nhop]);
		if(h->state == HS_SEND_FIN)
			espparam.flags = TH_FIN;
		else
		if(h->state == HS_SEND_SYN)
			espparam.flags = TH_SYN;
		else
		if(h->state == HS_SEND_SYN_ACK)
			espparam.flags = HS_SEND_SYN_ACK;
		else
		{
			WrnBadHopStateParam wbhsp;
			wbhsp.h=h;
			wbhsp.nhop=nhop;
			LFTErrHandler(sess, WRN_BAD_HOP_STATE, &wbhsp);
		}
	}
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
    packet->ip_hdr.ip_sum = ip_cksum (&packet->ip_hdr);
#endif
        
    memcpy(bptr, &(packet->ip_hdr), sizeof(struct ip));
    bptr += sizeof(struct ip);
    if (packet->lsrr.ipl_len > 0) {
        memcpy(bptr, &(packet->lsrr), packet->lsrr.ipl_len + 1);
        bptr += (packet->lsrr.ipl_len + 1); /* PADDING !!! */
    }
    
    /* Layer-4 preparation */
    
	/* Construct TCP (no payload needed) */
	if (sess->noisy > 5) 
	{
		LFTEvtHandler(sess,EVT_SHOW_PAYLOAD, packet);
		if(sess->exit_state < 0)
		{
			free(pinfo);
			return 0;
		}
	}
	packet->tcp_hdr.th_dport = dest.sin_port;
	packet->tcp_hdr.th_seq = htonl (tseq);
	packet->tcp_hdr.th_sport = htons (sess->sport);
	packet->tcp_hdr.th_flags = espparam.flags;
	
#if defined(SOLARIS_LENGTH_IN_CHECKSUM)
	packet->tcp_hdr.th_sum = htons (sizeof (struct tcphdr)) + packet->payload_len;
#else
	packet->tcp_hdr.th_sum = 0;
	packet->tcp_hdr.th_sum = tcp_cksum (&packet->ip_hdr, &packet->tcp_hdr, packet->payload, packet->payload_len);
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
    
    /* Packet is ready, fire away */
    if (sendto (sess->send_sock, buf, blen, 0, (const struct sockaddr *)(const void *)&dest, sizeof (dest)) < 0) {
        LFTErrHandler(sess, ERR_RAW_TCP_DISABLED, NULL);
        free(pinfo);
        return 0;
    }
	/*sess->debugmap[sess->debugmapidx].type=0;
	sess->debugmap[sess->debugmapidx].hop=nhop;
	sess->debugmap[sess->debugmapidx++].port=port;*/
	probeIsSent(sess, port, nhop);
    pinfo->hopno = nhop;
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

static void tcp_base_recv_packet (lft_session_params * sess, unsigned int seq, struct in_addr ipaddr, int icmp_type, const struct pcap_pkthdr *hdr)
{
    double ms;
    struct trace_packet_info_s *tp = NULL;
    EvtNonSeqPacketParam ensp;

    /* Depending on the platform, we can use
     * the pcap header's timeval or we must call
       gettimeofday() for each packet  */
    
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
    gettimeofday (&(sess->now), NULL);
#else
    sess->now.tv_sec = hdr->ts.tv_sec; 
    sess->now.tv_usec = hdr->ts.tv_usec;
    /* gettimeofday (&now, NULL); */
#endif
    
	/* First, search every probe to find an exact sequence match */
	SLIST_FOREACH(tp, &(sess->trace_packets), next)
	{
		if(tp->seq == seq)
			break;
	} 

#if 0
	if(tp == NULL)
	{
		/* Second, search every probe to find an exact port match */
		SLIST_FOREACH(tp, &(sess->trace_packets), next)
		{
			if(hopByPort(sess, htons(tp->packet.tcp_hdr.th_dport)) == tp->hopno)
				break;
		}
	}
#endif
    
    /* Last resort.  Catch any response from the target */
    if (tp == NULL) {
        if (sess->noisy > 3)
        {
            LFTEvtHandler(sess,EVT_LOOKFOR_LAST_RESORT,NULL);
            if(sess->exit_state < 0)
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
            LFTEvtHandler(sess, EVT_SKIP_PACKET, NULL);
        else
            if (!sess->nostatus)
		LFTEvtHandler(sess, EVT_PROGRESS_SKIP_PACKET, NULL);
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
    
	/*sess->debugmap[sess->debugmapidx].type=1;
	sess->debugmap[sess->debugmapidx].hop=tp->hopno;
	sess->debugmap[sess->debugmapidx].phop=hopByPort(sess, htons(tp->packet.tcp_hdr.th_dport));
	sess->debugmap[sess->debugmapidx].port=htons(tp->packet.tcp_hdr.th_dport);
	sess->debugmap[sess->debugmapidx++].ip=ipaddr;*/
	probeIsRecvd(sess, htons(tp->u.packet.tcp_hdr.th_dport));
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
				sess->hop_info[tp->hopno].done_packet = tp;
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

static void tcp_base_finish(lft_session_params * sess)
{
    int hopno;
    int maxhop;
    int reply, noreply;
    int as_for_hop = 0;
    struct trace_packet_info_s 	*tp;
    char *netname; 
	/*int ocres;*/
    char *myApp = (char *)malloc((strlen(version) * sizeof(char)) + 1 + (strlen(appname) * sizeof(char)));
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

    memset(ipaslist, '0', sizeof(struct ip_list_array));
    gettimeofday (&(sess->trace_done_time), NULL);
	/*ocres=open_check(sess, LFTErrHandler, LFTEvtHandler);
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
	}*/
    
    if (sess->noisy > 3)
    {
        LFTEvtHandler(sess,EVT_SHOW_NUM_HOPS, NULL);
        if(sess->exit_state < 0)
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
		{
            if (tp->is_done)
			{
                tp->hopno = maxhop;
				break;
			}
		}
    } else {
        maxhop = sess->hop_info_length - 1;
    }
    
    LFTEvtHandler(sess,EVT_TRACE_COMPLETED, NULL);
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
                    strcat(myApp,appname); strcat(myApp," "); 
		    strcat(myApp,version);
                    strncpy((*ipaslist).application, myApp, 511);
                }
                if (w_lookup_all_pwhois_bulk(sess->wsess, &(*ipaslist)) != 0)
                    if(sess->noisy)
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
				if(sess->exit_state < 0){
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
						int curroutputstyle=getOutputStyle();
						char hostname[100];
						ehip.seam_traced=1;
						setOutputStyle(2);
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
						ehip.is_open=subsess->target_open;
						ehip.is_filtered=subsess->target_filtered;
						LFTSessionClose(subsess);
						setOutputStyle(curroutputstyle);
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
	}

	if (!sess->num_hops) {
		LFTEvtHandler(sess,EVT_RPT_NO_HOPS,&maxhop);
	}
	if (sess->timetrace) {
		LFTEvtHandler(sess,EVT_RPT_TIME_TRACE,NULL);
	}
	LFTEvtHandler(sess,EVT_ON_EXIT,NULL);
	if(ipaslist != NULL)
		free(ipaslist);
} 

static int tcp_base_check_timeouts(lft_session_params * sess)
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
            tcp_base_send_hop(sess, nhop, 1);
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
					if(sess->hop_info[nhop].num_sent < sess->retry_max - 1)
						tcp_base_send_hop(sess, nhop, 1);
					else
					{
						sess->btcpdpucnt++;
						if(sess->btcpdpucnt>4)
						{
							sess->btcpdpucnt=0;
							sess->btcpmap[0].nhop=-1;
							sess->btcpmap[0].sentcount=0;
							tcp_base_send_hop(sess, nhop, 0);
						}
					}
                    return 0;
                }
				else
				{
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
            if(sess->exit_state < 0)
                return 0;
            tcp_base_finish(sess);
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
	    tcp_base_send_hop(sess, nhop, 1);
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
	        if (sess->hop_info[nhop].num_sent < sess->retry_min)
	        {
				tcp_base_send_hop(sess, nhop, 1);
	            return 0;
	        }
			if(sess->hop_info[nhop].done_packet)
			{
				if(sess->trg_probe_is_sent<sess->retry_min || (sess->trg_probe_is_sent<sess->retry_max && ntohs(sess->hop_info[nhop].done_packet->u.packet.tcp_hdr.th_dport)!=sess->dport))
				{
					sess->btcpdpucnt++;
					if(sess->btcpdpucnt>4)
					{
						sess->btcpdpucnt=0;
						sess->btcpmap[0].nhop=-1;
						sess->btcpmap[0].sentcount=0;
						sess->trg_probe_is_sent++;
						tcp_base_send_hop(sess, nhop, 0);
					}
					return 0;
				}
			}
	    }
    
	    tcp_base_finish(sess);
	    return 1;
	}
	return 0;
}

static void tcp_base_process_packet(lft_session_params * sess, const u_char *packet, const struct pcap_pkthdr *hdr)
{
    const struct ip *ip, *orig_ip;
    const struct tcphdr *tcp;
    const struct icmp *icmp;
    
    if (sess->noisy > 4)
    {
        LFTEvtHandler(sess,EVT_PROCESS_PACKET_START,NULL);
        if(sess->exit_state<0)
            return;
    }
    tcp_base_check_timeouts(sess);
    if(sess->exit_state<0)
        return;
    
    packet += sess->skip_header_len;
    ip = (const void *) packet;
            
    packet += 4 * ip->ip_hl;
            
    switch (ip->ip_p) {
        case IPPROTO_ICMP:
            orig_ip = ip;
            icmp = (const void *) packet;
            if (icmp->icmp_type != ICMP_UNREACH && icmp->icmp_type != ICMP_TIMXCEED)
                return;

			ip = &icmp->icmp_ip;
			if (ip->ip_p != IPPROTO_TCP)
				return;			/* not a response to our tcp probe */                
            packet = (const u_char *) ip;
            packet += 4 * ip->ip_hl;
            
			tcp = (const void *) packet;
			if (ip->ip_src.s_addr != sess->local_address.s_addr || ip->ip_dst.s_addr != sess->remote_address.s_addr)
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
			tcp_base_recv_packet(sess, ntohl (tcp->th_seq) , orig_ip->ip_src,
						 (icmp->icmp_type == ICMP_TIMXCEED) ? -2 : icmp->icmp_code, hdr);                        
            return;
            
        case IPPROTO_TCP:
            tcp = (const void *) packet;
            if (!(tcp->th_flags & TH_RST) && !(tcp->th_flags & TH_ACK) && !(tcp->th_flags & TH_SYN)) 
                return;			/* not what we're looking for */

            if (ip->ip_src.s_addr != sess->remote_address.s_addr || ip->ip_dst.s_addr != sess->local_address.s_addr) {
                return;			/* not the right connection */
            }
                    
            if (sess->noisy > 1) {
                LFTEvtHandler(sess,EVT_RCVD_TCP,tcp);
                if(sess->exit_state<0)
                    return;
            }
                    
                    
			if(ntohs(tcp->th_sport)==sess->dport)
			{
				/* Check for SYN,ACK in response to determine if target is listening */
				if ((tcp->th_flags & TH_ACK) && (tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_RST)) 
					sess->target_open++;
				if ((tcp->th_flags & TH_ACK) && !(tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_RST))
					sess->target_open = 0;
			}
                    
            tcp_base_recv_packet(sess, ntohl (tcp->th_ack) - 1, ip->ip_src, -1, hdr);
            return;
            
        default:
            if (sess->noisy > 3)
                LFTEvtHandler(sess,EVT_RCVD_UNKNOWN,ip);
    }
}

#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
void win_tcp_base_process(lft_session_params * sess)
{
    fd_set fds;
    struct timeval tm;
    tm.tv_sec = 0;
    tm.tv_usec = 100000;

    FD_ZERO(&fds);
    FD_SET(sess->recv_sock, &fds);
    if (select(sess->recv_sock+1, &fds, 0, 0, &tm) < 0)
	{
        LFTErrHandler(sess, ERR_WIN_SELECT, NULL);
        return;
    }
    if (FD_ISSET(sess->recv_sock, &fds))
	{
        /* read packet */
        char packetbuf[2048];
        int nread;
        memset(packetbuf, 0, sizeof(packetbuf));
        nread = recv(sess->recv_sock, packetbuf, sizeof(packetbuf), 0);
        if (nread <= 0)
		{
            LFTErrHandler(sess, ERR_WIN_RECV, NULL);
            return;
        }
        tcp_base_process_packet(sess, packetbuf, NULL);
    }
}
#else
static void pcap_tcp_base_process_packet(u_char * user_data, const struct pcap_pkthdr *hdr, const u_char * packet)
{
    lft_session_params * sess=(lft_session_params *)(void *)user_data;
	if(sess->exit_state<0)
		return;
    tcp_base_process_packet(sess, packet, hdr);
}
#endif

void tcp_base_trace_main_loop(lft_session_params * sess, LFT_CALLBACK err, LFT_CALLBACK evt)
{
	LFTErrHandler=err;
	LFTEvtHandler=evt;
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
	while(1)
	{
		win_tcp_base_process(sess);
		if(sess->exit_state<0)
			break;
		if(tcp_base_check_timeouts(sess))
			break;
		if(sess->exit_state<0)
			break;
	}
#else
	while(pcap_dispatch(sess->pcapdescr, -1, pcap_tcp_base_process_packet, (u_char *)sess) >= 0)
	{
		if(sess->exit_state<0)
			break;
		if(sess->noisy > 6)
		{
			LFTEvtHandler(sess,EVT_DBG_CHECKPOINT2,NULL);
			if(sess->exit_state<0)
				break;
		}
		if(tcp_base_check_timeouts(sess))
			break;
		if(sess->exit_state<0)
			break;
	}
#endif
}
