#include "lft_icmptrace.h"

static LFT_CALLBACK LFTErrHandler = NULL;
static LFT_CALLBACK LFTEvtHandler = NULL;

unsigned int icmp_rfc_send_request(lft_session_params * sess, LFT_CALLBACK err, LFT_CALLBACK evt);
unsigned int icmp_base_send_hop(lft_session_params * sess, LFT_CALLBACK err, LFT_CALLBACK evt, short nhop);
static void icmp_finish(lft_session_params *sess);

static u_short in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register u_short answer;
	register int sum = 0;

	while(nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if(nleft == 1)
	{
		u_short	u = 0;
		*(u_char *)(&u) = *(u_char *)w;
		sum += u;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}

/*
struct icmp_trace_packet_s
{
	char * packet;
	int packet_len;
	struct ip * ip_hdr;
	struct rfc1393_ip_option_s * icmp_trace_opt;
    	struct ip_lsrr * lsrr;
	struct icmp_echo_header_s * echo;;
    char * payload;
    int payload_len;
};
*/
#ifndef IPDEFTTL
#define IPDEFTTL 200
#endif
static const char payload_fill[]="VOSTROM";
int generateICMPPacket(
	lft_session_params * sess, 
	LFT_CALLBACK err, 
	LFT_CALLBACK evt, 
	struct icmp_trace_packet_s * packet, 
	u_char ttlval, 
	u_short unique_id,
	u_short seq)
{
	char * currptr;
	int i,j;
	int userlen;

	(void)evt;
	
	if(packet->packet)
		free(packet->packet);
	//size of ip header
	packet->packet_len=20;										//initial ip header
	if(sess->protocol==3)
		packet->packet_len+=12;									//trace option
	if(sess->hostname_lsrr_size)
		packet->packet_len+=(sess->hostname_lsrr_size + 1)*4;	//lsrr option
	//size of icmp header
	packet->packet_len+=sizeof(struct icmp_echo_header_s);		//icmp header
	//size of payload
	userlen=sess->userlen;
	if(userlen)
	{
		userlen -= packet->packet_len;
		if(userlen<0)
			userlen = 0;
		if(userlen%4)
			userlen+=4-(userlen%4);
	}
	packet->packet_len+=userlen;
	if(!(packet->packet=malloc(packet->packet_len)))
	{
		err(sess, ERR_NOT_ENOUGH_MEM, NULL);
		return 0;
	}
	memset(packet->packet, 0,packet->packet_len);
	//initialize ip header
	currptr = packet->packet;
	packet->ip_hdr = (struct ip *)(void *)packet->packet;
	packet->ip_hdr->ip_v = 4;
	packet->ip_hdr->ip_hl = 5;
	if(sess->hostname_lsrr_size)
		packet->ip_hdr->ip_hl +=  sess->hostname_lsrr_size + 1;
	if(sess->protocol == 3)
		packet->ip_hdr->ip_hl += 3;
	packet->ip_hdr->ip_id = unique_id;
	if(sess->set_tos) 
		packet->ip_hdr->ip_tos = TOSMINDELAY;
	else
		packet->ip_hdr->ip_tos = 0;
	packet->ip_hdr->ip_off = IP_DF;
	packet->ip_hdr->ip_len = packet->packet_len;
#ifndef SCREWED_IP_LEN
	packet->ip_hdr->ip_off = htons(packet->ip_hdr->ip_off);
	packet->ip_hdr->ip_len = htons(packet->ip_hdr->ip_len);
#endif
	packet->ip_hdr->ip_p = IPPROTO_ICMP;
    	packet->ip_hdr->ip_src = sess->local_address;
    	packet->ip_hdr->ip_dst = sess->remote_address;
	if(sess->protocol==3)
		packet->ip_hdr->ip_ttl = IPDEFTTL;
	else
		packet->ip_hdr->ip_ttl = ttlval;
	currptr += sizeof(struct ip);
	//initialize ip option for rfc1393 trace
	/*
	struct rfc1393_ip_option_s
	{
		u_char optcode;		//=82
		u_char optlength;	//=12
		u_short id;			//number to identify icmp trace messages
		u_short ohc;			//outbound hop count
		u_short rhc;			//return hop count
		struct in_addr origip;		//originator ip address
	};
	*/
	if(sess->protocol == 3)
	{
		packet->icmp_trace_opt = (struct rfc1393_ip_option_s *)(void *)currptr;
		packet->icmp_trace_opt->optcode = 82;
		packet->icmp_trace_opt->optlength = 12;
		packet->icmp_trace_opt->id = seq;
		packet->icmp_trace_opt->ohc = 0;
		packet->icmp_trace_opt->rhc = 0xFFFF;
		packet->icmp_trace_opt->origip = sess->local_address;
		currptr+=sizeof(struct rfc1393_ip_option_s);
	}
	else
		packet->icmp_trace_opt = NULL;
	/*
	struct ip_lsrr {
	    u_int8_t ipl_code;
	    u_int8_t ipl_len;
	    u_int8_t ipl_ptr;
	    u_int32_t data[9];
		 char padding[1];
	} __attribute__((packed));
	*/
	if(sess->hostname_lsrr_size)
	{
		packet->lsrr=(struct ip_lsrr *)(void *)currptr;
		currptr+=(sess->hostname_lsrr_size + 1)*4;
		for(i = 0; i < sess->hostname_lsrr_size; i++)
			packet->lsrr->data[i] = get_address(sess, sess->hostname_lsrr[i]);
		packet->lsrr->ipl_code = IPOPT_LSRR;
		packet->lsrr->ipl_len = sess->hostname_lsrr_size * 4 + 3;
		packet->lsrr->ipl_ptr = 4;
	}
	packet->ip_hdr->ip_sum = 0;
#ifndef SCREWED_IP_LEN
	packet->ip_hdr->ip_sum = ip_cksum(packet->ip_hdr);
#endif
	/*
	struct icmp_echo_header_s
	{
		u_char type;
		u_char code;
		u_short checksum;
		u_short id;
		u_short sequence;
	};
	*/
	packet->echo=(struct icmp_echo_header_s *)(void *)currptr;
	currptr+=sizeof(struct icmp_echo_header_s);
	packet->echo->type=ICMP_ECHO;
	packet->echo->code=0;
	packet->echo->checksum=0;
	packet->echo->id=unique_id;
	packet->echo->sequence=seq;
	if(userlen)
	{
		packet->payload=currptr;
		for(i=0,j=0;i<userlen;i++,j++)
		{
			if(!payload_fill[j])
				j=0;
			currptr[i]=payload_fill[j];
		}
	}
	else
		packet->payload=NULL;
	packet->payload_len = userlen;
    	sess->payload = NULL;
    	sess->payloadlen = userlen;
	packet->echo->checksum=in_cksum((u_short *)(void *)packet->echo, sizeof(struct icmp_echo_header_s)+packet->payload_len);
/*#ifndef SCREWED_IP_LEN
	packet->echo->checksum = htons(packet->echo->checksum);
#endif*/
	return packet->packet_len;
}

static int icmp_check_timeouts (lft_session_params * sess, LFT_CALLBACK err, LFT_CALLBACK evt)
{
    int nhop;
    int need_reply = 0;
    int no_reply = 0;
    int last_return = 0;

	LFTErrHandler=err;
	LFTEvtHandler=evt;

    gettimeofday (&(sess->now), NULL);
    if (timediff_ms(sess->ts_last_sent, sess->now) < sess->scatter_ms)
        return 0;			/* not ready to send another packet yet */
	if(sess->protocol==2)
	{
		for(nhop = sess->ttl_min; nhop < sess->hop_info_length; nhop++)
		{
	        if(!sess->hop_info[nhop].num_sent)
			{
	            icmp_base_send_hop(sess, err, evt, nhop);
	            return 0;
	        }
	    }
	    for(nhop = sess->ttl_min; nhop < sess->hop_info_length; nhop++)
		{
	        if(sess->hop_info[nhop].num_sent <= sess->retry_max && !sess->hop_info[nhop].ts_last_recv.tv_sec)
			{
	            if(sess->noisy > 4)
	            {
	                evt(sess,EVT_TTL_NO_REPLY,&nhop);
	                if(sess->exit_state<0)
	                    return 0;
	            }
	            if(timediff_ms(sess->hop_info[nhop].ts_last_sent, sess->now) >= sess->timeout_ms)
				{
	                /* we timed out waiting for this hop -- retry if we have any
	                * more tries */
	                if(sess->hop_info[nhop].num_sent < sess->retry_max)
					{
	                    if(!sess->noisy && !sess->nostatus)
	                        evt(sess,EVT_PROGRESS_NO_REPLY,NULL);
	                    if(sess->noisy > 2)
	                        evt(sess,EVT_TTL_TOUT_RESEND,&nhop);
	                    if(sess->exit_state<0)
	                        return 0;
	                    icmp_base_send_hop(sess, err, evt, nhop);
	                    return 0;
	                }
					else
					{
						no_reply++;
					}
	            }
				else
					need_reply++;		/* we have to wait for this one to timeout */
	        }
			else	/* have reply */
				last_return = nhop;
	    }
	}
	else
	{
		if(!sess->hop_info[255].num_sent)
		{
            icmp_rfc_send_request(sess, err, evt);
            return 0;
        }
	    if(sess->hop_info[255].num_sent <= sess->retry_max && !sess->hop_info[255].ts_last_recv.tv_sec)
		{
	        if(sess->noisy > 4)
	        {
	            evt(sess,EVT_TTL_NO_REPLY,&nhop);
	            if(sess->exit_state<0)
	                return 0;
	        }
	        if(timediff_ms(sess->hop_info[255].ts_last_sent, sess->now) >= sess->timeout_ms)
			{
	            /* we timed out waiting for this hop -- retry if we have any
	            * more tries */
	            if(sess->hop_info[255].num_sent < sess->retry_max)
				{
	                if(!sess->noisy && !sess->nostatus)
	                    evt(sess,EVT_PROGRESS_NO_REPLY,NULL);
	                if(sess->noisy > 2)
	                    evt(sess,EVT_TTL_TOUT_RESEND,&nhop);
	                if(sess->exit_state<0)
	                    return 0;
	                icmp_rfc_send_request(sess, err, evt);
	                return 0;
	            }
				else
					no_reply++;
	        }
			else
				need_reply++;		/* we have to wait for this one to timeout */
		}
		else	/* have reply */
			last_return = 0;
	}
    if(sess->noisy > 4)
	{
        EvtDebugCheckpoint1Param edcp;
        edcp.last_return=last_return;
        edcp.need_reply=need_reply;
        edcp.no_reply=no_reply;
        evt(sess,EVT_DBG_CHECKPOINT1,&edcp);
        if(sess->exit_state<0)
            return 0;
    }
    if(no_reply >= sess->ahead_limit)
	{	/* we timed out. */
		if((last_return + 3) * 2 < sess->hop_info_length)
		{
			if((need_reply < 3) && (sess->num_rcvd < 2))
				evt(sess,EVT_CANT_RELIABLY_RTRIP,NULL);
            if(sess->exit_state<0)
                return 0;
            icmp_finish(sess);
            return 1;
        }
    }
	if((!sess->num_hops || sess->hop_info_length < sess->num_hops || need_reply) && sess->hop_info_length < sess->ttl_limit)
	{
		if(sess->noisy > 4)
			evt(sess,EVT_HAVE_UNANSWERRED_HOPS,NULL);
	    	if(need_reply >= sess->ahead_limit){
			if(sess->noisy > 4)
				evt(sess,EVT_TOO_FAR_AHEAD,NULL);
	        	return 0;	/* wait for some replies before we go on */
	    	}
		if(sess->exit_state<0)
	        	return 0;
    
		if(sess->num_hops > 0 && sess->hop_info_length >= sess->num_hops)
		{
	        	if(sess->noisy > 3)
				evt(sess,EVT_HAVE_GAPS,NULL);
	        	return 0;	/* we know how long the path is - wait to fill in the blanks      */
	    	}
    
	    	nhop = sess->hop_info_length++;
		if(sess->protocol==2)
			icmp_base_send_hop(sess, err, evt, nhop);
		else
		{
			icmp_rfc_send_request(sess, err, evt);
		}
	}
	else
	{ 
	    if (sess->noisy >= 4)
	    {
	        evt(sess, EVT_EITHER_RESP_OR_TOUT, NULL);
	        if(sess->exit_state < 0)
	            return 0;
	    }
		if(sess->protocol == 2)
		{
		    for(nhop = sess->ttl_min; nhop < sess->hop_info_length; nhop++)
		    {
		        if (sess->hop_info[nhop].num_sent < sess->retry_min && sess->hop_info[nhop].num_sent <= sess->retry_max)
		        {
		            icmp_base_send_hop(sess, err, evt, nhop);
		            return 0;
		        }
		    }
		}
		else
		{
	        	if(sess->hop_info[255].num_sent < sess->retry_min && sess->hop_info[255].num_sent <= sess->retry_max)
	        	{
	            		icmp_rfc_send_request(sess, err, evt);
		            	return 0;
		        }
		}
	    icmp_finish(sess);
	    return 1;
	}
	return 0;
}

unsigned int icmp_rfc_send_request(lft_session_params * sess, LFT_CALLBACK err, LFT_CALLBACK evt)
{
	struct trace_packet_info_s *pinfo = NULL;
	struct sockaddr_in dest;
	u_short rfc_unique_seq;
	unsigned int nseq;

	dest.sin_family = AF_INET;
    	dest.sin_addr = sess->remote_address;
    	dest.sin_port = 0;    

	if(!(pinfo = (struct trace_packet_info_s *)malloc(sizeof(struct trace_packet_info_s))))
	{
		err(sess, ERR_NOT_ENOUGH_MEM, NULL);
		return 0;
	}
	memset(pinfo, 0, sizeof(struct trace_packet_info_s));
	nseq = new_seq(sess);
	nseq &= 0xFFFF;
	rfc_unique_seq = nseq;
	generateICMPPacket(sess, err, evt, &pinfo->u.icmp_packet, 0, sess->icmp_packet.echo->id, rfc_unique_seq);
    	/* Packet is ready, fire away */
    	if(sendto(sess->send_sock, pinfo->u.icmp_packet.packet, pinfo->u.icmp_packet.packet_len, 0, (const struct sockaddr *)(const void *)&dest, sizeof (dest)) < 0)
	{
        	LFTErrHandler(sess, ERR_RAW_TCP_DISABLED, NULL);
        	free(pinfo);
        	return 0;
    	}
	pinfo->hopno = 0;
	pinfo->seq = rfc_unique_seq;
    	pinfo->sent = sess->now;
    	SLIST_INSERT_HEAD(&(sess->trace_packets), pinfo, next);
    	sess->trace_packets_num++;
    	/* we use special hop_info #255 */
	SLIST_INSERT_HEAD(&(sess->hop_info[255].packets), pinfo, next_by_hop);
    	sess->hop_info[255].num_sent++;
    	sess->hop_info[255].all_sent++;
    	sess->hop_info[255].ts_last_sent = sess->now;
	return 1;
}

unsigned int icmp_base_send_hop(lft_session_params * sess, LFT_CALLBACK err, LFT_CALLBACK evt, short nhop)
{
	struct trace_packet_info_s *pinfo = NULL;
	struct sockaddr_in dest;
	u_short base_unique_seq;
	unsigned int nseq;
    	EvtSentPacketParam espparam;

    	dest.sin_family = AF_INET;
    	dest.sin_addr = sess->remote_address;
    	dest.sin_port = 0;    

	nseq = new_seq(sess);
	nseq &= 0xFFFF;
	base_unique_seq = nseq;

	sess->ts_last_sent = sess->now;
	
	if(!(pinfo = (struct trace_packet_info_s *)malloc(sizeof(struct trace_packet_info_s))))
	{
		err(sess, ERR_NOT_ENOUGH_MEM, NULL);
		return 0;
	}
	memset(pinfo, 0, sizeof(struct trace_packet_info_s));
    	espparam.flags=0;
    	espparam.nhop=nhop;
    	espparam.tseq=base_unique_seq;
    	espparam.tttl=nhop+1;
    	if (sess->noisy > 1)
    	{
        	LFTEvtHandler(sess,EVT_SENT_PACKET, &espparam);
        	if(sess->exit_state <0 )
        	{
	    		free(pinfo);
            		return 0;
        	}
    	}
	generateICMPPacket(sess, err, evt, &pinfo->u.icmp_packet, nhop+1, sess->icmp_packet.echo->id, base_unique_seq);
    	/* Packet is ready, fire away */
    	if(sendto(sess->send_sock, pinfo->u.icmp_packet.packet, pinfo->u.icmp_packet.packet_len, 0, (const struct sockaddr *)(const void *)&dest, sizeof (dest)) < 0)
	{
		/* printf("errno=%d\n",errno); */
        	LFTErrHandler(sess, ERR_RAW_TCP_DISABLED, NULL);
        	free(pinfo);
        	return 0;
    	}
    	pinfo->hopno = nhop;
	pinfo->seq = base_unique_seq;
    	pinfo->sent = sess->now;
    	SLIST_INSERT_HEAD(&(sess->trace_packets), pinfo, next);
    	sess->trace_packets_num++;
    
    	if(nhop != -1)
	{
        	SLIST_INSERT_HEAD(&(sess->hop_info[nhop].packets), pinfo, next_by_hop);
        	sess->hop_info[nhop].num_sent++;
        	sess->hop_info[nhop].all_sent++;
        	sess->hop_info[nhop].ts_last_sent = sess->now;
    	}
	return 1;
}

static int icmp_recv_packet (lft_session_params * sess, unsigned int seq, struct in_addr ipaddr, int icmp_type, const void * pack, const struct pcap_pkthdr *hdr)
{
	struct trace_packet_info_s *tp = NULL, *pinfo = NULL;
	const struct icmp_trace_reply_header_s *icmpheader = (const struct icmp_trace_reply_header_s *)pack;
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
	gettimeofday (&(sess->now), NULL);
#else
	sess->now.tv_sec = hdr->ts.tv_sec; 
	sess->now.tv_usec = hdr->ts.tv_usec;
#endif
	/* First, search every probe to find an exact sequence match */
	SLIST_FOREACH(tp, &(sess->trace_packets), next)
	{
		if(tp->seq == seq)
		{
			break;
		}
	}
	if(!tp)
	{
        if (sess->noisy)
            LFTEvtHandler(sess,EVT_SKIP_PACKET,NULL);
        else
            if (!sess->nostatus) 
			LFTEvtHandler(sess,EVT_PROGRESS_SKIP_PACKET,NULL);
		return 0;
	}
    if (tp->recv.tv_sec)
	{
        if (sess->noisy)
            LFTEvtHandler(sess,EVT_DUPLICATE_PACKET, NULL);
        else
            if (!sess->nostatus)
                LFTEvtHandler(sess,EVT_PROGRESS_DUPLICATE,NULL);
        return 0;
    }
    if (sess->noisy > 1) 
    {
        EvtRecvPacketParam erpp;
        erpp.ipaddr=ipaddr;
        erpp.seq=seq;
        erpp.tp=tp;
        LFTEvtHandler(sess,EVT_RECV_PACKET,&erpp);
    }
    else
	{
        if (!sess->nostatus)
	{
            LFTEvtHandler(sess,EVT_PROGRESS_OK,NULL);
	}
    }
    if(sess->exit_state < 0)
        return 0;
    /* increment received packet counter */
    sess->num_rcvd++;
    tp->recv = sess->now;
    if (tp->hopno != -1)
	{
		if(sess->protocol==3 && icmp_type == ICMP_TRACE)
		{
			tp->hopno=icmpheader->ohc;
		    	sess->hop_info[tp->hopno].num_sent = sess->hop_info[255].num_sent;
		    	sess->hop_info[tp->hopno].all_sent = sess->hop_info[255].all_sent;
		    	sess->hop_info[tp->hopno].ts_last_sent = sess->hop_info[255].ts_last_sent;
			sess->hop_info[tp->hopno].state = sess->hop_info[255].state;
			sess->hop_info[tp->hopno].flags = sess->hop_info[255].flags;
		}
        sess->hop_info[tp->hopno].ts_last_recv = sess->now;
        sess->hop_info[tp->hopno].all_rcvd++;
        /* indicate this hop has a sequence anomaly */
        if(icmp_type==ICMP_UNREACH || icmp_type==ICMP_TIMXCEED)
            sess->hop_info[tp->hopno].flags |= HF_ENDPOINT;
    }
    
    tp->recv = sess->now;
    tp->hopaddr = ipaddr;
	if(icmp_type==ICMP_TIMXCEED)
		tp->icmp_type = -2;
	else
		if(icmp_type == ICMP_ECHOREPLY)
			tp->icmp_type = -1;
		else
			tp->icmp_type = icmp_type;

	if(icmp_type == ICMP_ECHOREPLY && ipaddr.s_addr == sess->remote_address.s_addr)
	{
		if(sess->protocol==3)
		{
			tp->hopno=sess->num_hops+1;
		    	sess->hop_info[tp->hopno].num_sent = sess->hop_info[255].num_sent;
		    	sess->hop_info[tp->hopno].all_sent = sess->hop_info[255].all_sent;
		    	sess->hop_info[tp->hopno].ts_last_sent = sess->hop_info[255].ts_last_sent;
			sess->hop_info[tp->hopno].state = sess->hop_info[255].state;
			sess->hop_info[tp->hopno].flags = sess->hop_info[255].flags;
			sess->hop_info[tp->hopno].ts_last_recv = sess->now;
			sess->hop_info[tp->hopno].all_rcvd++;
		}
		if(!sess->num_hops)
		{
			sess->num_hops = tp->hopno;
			if(!sess->num_hops)
				sess->num_hops=1;
		}
		tp->is_done = 1;
	}
	else
	{
		if(icmp_type == ICMP_UNREACH || icmp_type == ICMP_TIMXCEED)
			return 1;
		if(sess->protocol == 3 && icmp_type == ICMP_TRACE)
		{
			if(icmpheader->rhc == 0xFFFF)	/* outbound packet */
			{
				if(!(pinfo = (struct trace_packet_info_s *)malloc(sizeof(struct trace_packet_info_s))))
				{
					LFTErrHandler(sess, ERR_NOT_ENOUGH_MEM, NULL);
					return 0;
				}
				memcpy(pinfo, tp, sizeof(struct trace_packet_info_s));
		        	SLIST_INSERT_HEAD(&(sess->hop_info[tp->hopno].packets), pinfo, next_by_hop);
			}
			else
				return 1;					//while ignore return packets
		}
	}
	return 1;
}

static void icmp_process_packet(lft_session_params * sess, LFT_CALLBACK err, LFT_CALLBACK evt, const u_char *packet, const struct pcap_pkthdr *hdr)
{
    	const struct ip *ip, *orig_ip;
    	const struct icmp *icmp;
	const struct icmp_echo_header_s *orig_echo, *resp_echo;

	LFTErrHandler=err;
	LFTEvtHandler=evt;

    	if(sess->noisy > 4)
    	{
        	LFTEvtHandler(sess,EVT_PROCESS_PACKET_START,NULL);
        	if(sess->exit_state<0)
            	return;
    	}
	icmp_check_timeouts(sess, err, evt);
    	if(sess->exit_state<0)
        	return;    
    	packet += sess->skip_header_len;
    	ip = (const void *) packet;
            
    	packet += 4 * ip->ip_hl;            
    	switch(ip->ip_p){
	case IPPROTO_ICMP:
		orig_ip = ip;
		icmp = (const void *) packet;
		if(icmp->icmp_type != ICMP_ECHOREPLY && icmp->icmp_type != ICMP_UNREACH && !(sess->protocol==2 && icmp->icmp_type == ICMP_TIMXCEED) && !(sess->protocol==3 && icmp->icmp_type == ICMP_TRACE))
			return;
		if(icmp->icmp_type == ICMP_ECHOREPLY)
		{
			resp_echo=(const struct icmp_echo_header_s *)icmp;
			if(resp_echo->id != sess->icmp_packet.echo->id)
				return;
			if (sess->noisy > 2) {
				EvtIncomingICMPEchoParam echo;
				echo.ip=orig_ip;
				echo.echo=resp_echo;
				LFTEvtHandler(sess,EVT_INCOMING_ICMP_Echo,&echo);
				if(sess->exit_state<0)
					return;
			}
			if (sess->noisy > 1) 
			{
				LFTEvtHandler(sess,EVT_RCVD_ICMP_Echo,resp_echo);
				if(sess->exit_state<0)
					return;
			}
				
			icmp_recv_packet(sess, resp_echo->sequence, orig_ip->ip_src, ICMP_ECHOREPLY, NULL, hdr);
            		return;
		}
		if(icmp->icmp_type == ICMP_UNREACH || icmp->icmp_type == ICMP_TIMXCEED)
		{
			ip = &icmp->icmp_ip;
			if(ip->ip_p != IPPROTO_ICMP)
				return;
			packet = (const u_char *) ip;
			packet += 4 * ip->ip_hl;
			orig_echo = (const struct icmp_echo_header_s *)packet;
			if(orig_echo->type != ICMP_ECHO)
				return;
			if(sess->icmp_packet.echo->id != orig_echo->id)
				return;
			if (sess->noisy > 2) {
				EvtIncomingICMPICMPParam icmpicmp;
				icmpicmp.ip=orig_ip;
				icmpicmp.icmp=icmp;
				icmpicmp.orig_ip=ip;
				icmpicmp.echo=orig_echo;
				LFTEvtHandler(sess,EVT_INCOMING_ICMP_ICMP,&icmpicmp);
				if(sess->exit_state<0)
					return;
			}
			if (sess->noisy > 1) 
			{
				LFTEvtHandler(sess,EVT_RCVD_ICMP_ICMP,icmp);
				if(sess->exit_state<0)
					return;
			}
			icmp_recv_packet(sess, orig_echo->sequence, orig_ip->ip_src, icmp->icmp_type, NULL, hdr);
            return;
		}
		if(icmp->icmp_type == ICMP_TRACE)
		{
			const struct icmp_trace_reply_header_s * itrh=(const struct icmp_trace_reply_header_s *)icmp;
			icmp_recv_packet(sess, itrh->id, orig_ip->ip_src, itrh->type, itrh, hdr);
            return;
		}
	default:
		if(sess->noisy > 3)
			LFTEvtHandler(sess,EVT_RCVD_UNKNOWN,ip);
	}
}

#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
void win_icmp_process(lft_session_params * sess)
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
        icmp_process_packet(sess, LFTErrHandler, LFTEvtHandler, packetbuf, NULL);
    }
}
#else
static void pcap_icmp_process_packet(u_char * user_data, const struct pcap_pkthdr *hdr, const u_char * packet)
{
    lft_session_params * sess=(lft_session_params *)(void *)user_data;
	if(sess->exit_state<0)
		return;
    icmp_process_packet(sess, LFTErrHandler, LFTEvtHandler, packet, hdr);
}
#endif

void icmp_trace_main_loop(lft_session_params * sess, LFT_CALLBACK err, LFT_CALLBACK evt)
{
	LFTErrHandler=err;
	LFTEvtHandler=evt;
#if defined( __CYGWIN__ ) || defined( WIN32 ) || defined(_WIN32)
	while(1)
	{
		win_icmp_process(sess);
		if(sess->exit_state < 0)
			break;
		if(icmp_check_timeouts(sess, err, evt))
			break;
		if(sess->exit_state < 0)
			break;
	}
#else
	while(pcap_dispatch(sess->pcapdescr, -1, pcap_icmp_process_packet, (u_char *)sess) >= 0)
	{
		if(sess->exit_state < 0)
			break;
		if(sess->noisy > 6)
		{
			LFTEvtHandler(sess, EVT_DBG_CHECKPOINT2, NULL);
			if(sess->exit_state < 0)
				break;
		}
		if(icmp_check_timeouts(sess,err,evt))
			break;
		if(sess->exit_state<0)
			break;
	}
#endif
}

static 
void icmp_finish(lft_session_params *sess)
{
    int hopno;
    int maxhop;
    int reply, noreply;
    int as_for_hop = 0;
    struct trace_packet_info_s *tp;
    char *netname; 
    /* int ocres; */
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

    memset(ipaslist, 0, sizeof(struct ip_list_array));
    gettimeofday (&(sess->trace_done_time), NULL);
    /*
	ocres=open_check(sess);
	LFTEvtHandler(sess,EVT_OPEN_CHECK_RESULT,&ocres);
	if(ocres==1)
		sess->target_open=1;
	else
		sess->target_open=0;
     */
    if (sess->noisy > 3)
    {
        LFTEvtHandler(sess, EVT_SHOW_NUM_HOPS, NULL);
        if(sess->exit_state < 0)
        {
	    free(ipaslist);
            free(myApp);
            return;
        }
    }
    if(sess->num_hops)
	{
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
    }
	else
	{
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
    if (sess->do_aslookup || sess->do_netlookup)
	{
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
        if (!sess->use_radb)
		{
            /* populate bulk ip_addr_list structure */
            for (hopno = sess->ttl_min; hopno <= maxhop; hopno++)
			{
                SLIST_FOREACH(tp, &(sess->hop_info[hopno].packets), next_by_hop)
				{
                    if (tp->recv.tv_usec)
					{
                        (*ipaslist).ipaddr[as_for_hop] = tp->hopaddr;
                        as_for_hop++;
                        (*ipaslist).numItems = (as_for_hop);
                        break;
                    }
                }
            }
            if (sess->use_cymru)
			{         /* use cymru bulk service */
                if (w_lookup_as_cymru_bulk(sess->wsess, &(*ipaslist)) != 0)
                    if (sess->noisy) LFTErrHandler(sess, WRN_NS_LOOKUP_FAILED, NULL);
            }
			else 
				if (sess->use_ris)
				{    /* use RIPE NCC RIS service */
					if (w_lookup_all_riswhois_bulk(sess->wsess, &(*ipaslist)) != 0)
						if (sess->noisy)
							LFTErrHandler(sess, WRN_NS_LOOKUP_FAILED, NULL);
				}
				else
				{       /* use pwhois bulk service */
					if ((strlen(version) * sizeof(char)) + 1 + (strlen(appname) * sizeof(char)) < 254)
					{
						*myApp = '\0';
						strcat(myApp, appname);
						strcat(myApp, " ");
						strcat(myApp, version);
						strncpy((*ipaslist).application, myApp, 511);
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


	for (hopno = sess->ttl_min; hopno <= maxhop; hopno++)
	{
		struct in_addr last_hop;
    
		if (sess->hop_info[hopno].all_rcvd != 0)
		{
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
		if ((sess->hop_info[hopno].state == HS_SEND_FIN) && (sess->hop_info[hopno+1].state == HS_SEND_SYN) && (sess->hop_info[hopno+1].ts_last_recv.tv_sec))
		{
			LFTEvtHandler(sess,EVT_RPT_FRW_INSPECT_PACKS, NULL);
                        if(sess->exit_state < 0){
                        	free(ipaslist);
                         	return;
                        }
 		}

		if ((sess->hop_info[hopno].state != HS_SEND_SYN_ACK) && (sess->hop_info[hopno+1].state == HS_SEND_SYN_ACK) && (hopno == (sess->num_hops - 1)))
		{
			LFTEvtHandler(sess,EVT_RPT_FRW_STATE_FILTER, NULL);
                        if(sess->exit_state < 0){
                        	free(ipaslist);
                        	return;
                        }
		}    
    
		if ((sess->hop_info[hopno].flags & HF_ENDPOINT) && (noreply >= ((maxhop - sess->ttl_min)/2)) && sess->num_hops > 3)
		{
			LFTEvtHandler(sess,EVT_RPT_BSD_BUG, NULL);
                        if(sess->exit_state < 0){
                                free(ipaslist);
                                return;
                        }
		}
    
		if (sess->hop_info[hopno].all_rcvd == 0)
		{
			reply = 0;
		}
		else
		{
			LFTEvtHandler(sess,EVT_RPT_HOP_INFO_START,&hopno);
                        if(sess->exit_state < 0){
                                free(ipaslist);
                                return;
                        }
        
			//printf("hopno=%d all_rcvd=%d",hopno,sess->hop_info[hopno].all_rcvd);
			SLIST_FOREACH(tp, &(sess->hop_info[hopno].packets), next_by_hop)
			{
				if (tp->recv.tv_sec)
				{
					reply = 1;
                                                                
					if (last_hop.s_addr != tp->hopaddr.s_addr)
					{
						ehip.asnumber = 0; 	/* init/clear the ASN */
						if (sess->do_aslookup)
						{
							if (sess->use_radb)
							{ 
								/* using RADB/IRR */
								ehip.asnumber = w_lookup_as(sess->wsess, inet_ntoa(tp->hopaddr));
							}
							else
							{
								/* using pwhois by default */
								ehip.asnumber = (*ipaslist).asn[as_for_hop];
							}
						}
						tp->asnumber=ehip.asnumber;
						ehip.netname=NULL;
						if (sess->do_netlookup)
						{
							if (!sess->do_aslookup || (sess->do_aslookup && !sess->use_cymru && !sess->use_radb))
							{
								netname = (*ipaslist).netName[as_for_hop];
							}
							else
							{
								netname = w_lookup_netname(sess->wsess, inet_ntoa(tp->hopaddr));
							}
							ehip.netname = netname;
						}
						if(ehip.netname)
							strncpy(tp->netname, ehip.netname, 511);
						else
							tp->netname[0]=0;
					}
					ehip.last_hop = last_hop;
					tp->last_hop=ehip.last_hop;
					last_hop = tp->hopaddr;
				}
				ehip.tp = tp;
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
		if (reply)
		{
			noreply = 0;
			as_for_hop++;
		}
		else
			noreply++;
    
		reply = 0;
	} /* for(...) */

	if (!sess->num_hops)
	{
		LFTEvtHandler(sess,EVT_RPT_NO_HOPS,&maxhop);
	}
	if (sess->timetrace)
	{
		LFTEvtHandler(sess,EVT_RPT_TIME_TRACE,NULL);
	}
	LFTEvtHandler(sess,EVT_ON_EXIT,NULL);
	free(ipaslist);
	return;
} 
