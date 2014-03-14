

#ifndef EC_PING_H
#define EC_PING_H

/* exported functions */
EC_API_EXTERN int do_ping(char *, char *, size_t, int);
EC_API_EXTERN int do_geoip(char *, char *, size_t);
EC_API_EXTERN void ping_init(void);

#endif

/* EOF */

// vim:ts=3:expandtab

