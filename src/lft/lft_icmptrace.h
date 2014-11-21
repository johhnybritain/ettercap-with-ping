#ifndef LFT_ICMPTRACE_H
#define LFT_ICMPTRACE_H

#include "lft_lib.h"

#define ICMP_TRACE	30

int generateICMPPacket(
	lft_session_params * sess, 
	LFT_CALLBACK err, 
	LFT_CALLBACK evt, 
	struct icmp_trace_packet_s * packet, 
	u_char ttlval, 
	u_short unique_id,
	u_short seq);
void icmp_trace_main_loop(lft_session_params * sess, LFT_CALLBACK err, LFT_CALLBACK evt);
#endif
