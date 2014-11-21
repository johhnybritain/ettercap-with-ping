/*
 *  lft_lsrr.h
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

#ifndef LFT_LSRR_H
#define LFT_LSRR_H

#if defined(sun)
typedef uint8_t u_int8_t;
typedef uint32_t u_int32_t;
#endif

struct ip_lsrr {
    u_int8_t ipl_code;			/* IPOPT_TS */
    u_int8_t ipl_len;			/* size of structure (variable) */
    u_int8_t ipl_ptr;			/* index of current entry */
    u_int32_t data[9];
	 char padding[1];
} __attribute__((packed));
#define IP_LSRR_DEST		8


#endif
