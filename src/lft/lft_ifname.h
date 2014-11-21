/*
 *  lft_ifname.h
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

#ifndef LFT_IFNAME_H
#define LFT_IFNAME_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	STRNCPY(dst, src, len)	{	\
	(dst)[(len)-1] = '\0';		\
	strncpy((dst),(src),(len)-1);	\
}

extern u_long		lft_getifaddr (const char *);
extern char *		lft_getifname (struct in_addr);

#ifdef	__cplusplus
}
#endif

#endif /*LFT_IFNAME_H*/
