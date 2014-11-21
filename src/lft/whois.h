/*
 *  whois.h
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

#ifndef WHOIS_H
#define WHOIS_H

#define LFT_STANALONE 1

struct ip_list_array {
	struct in_addr ipaddr[1024];
	int  asn[1024];
    char netName[1024][32];
    char orgName[1024][100];
    char application[1024];
	int  numItems;
};

struct ext_ip_list_array {
	struct in_addr ipaddr[1024];
	int  asn[1024];
	char prefix[1024][20];
    char netName[1024][32];
    char orgName[1024][100];
    char application[1024];
    double latitude[1024];
    double longitude[1024];
    char country[1024][50];
    char state[1024][50];
    char city[1024][50];
    char asOrgNameSource[1024][100];
    char orgNameSource[1024][100];
    char netNameSource[1024][100];
    int geoavailable;
	int  numItems;
};
#ifdef	__cplusplus
extern "C" {
#endif
typedef struct _whoissessionparams
{
    int w_noisy;                   /* Don't show debug msgs by default */
    char pw_serv[256];                 /* User can specify his own pwhois server */
    char consolidated_asn[256];        /* ASN returned from pwhois */
    char consolidated_asp[256];        /* AS-PATH returned from pwhois */
    char consolidated_route[256];      /* Prefix returned from pwhois */
    char consolidated_asorgname[256];  /* AS-OrgName returned from pwhois */
    char consolidated_orgname[256];    /* OrgName returned from pwhois */
    char consolidated_netname[256];    /* NetName returned from pwhois */
    char consolidated_city[256];       /* City returned from pwhois */
    char consolidated_region[256];     /* Region returned from pwhois */
    char consolidated_country[256];    /* Country returned from pwhois */
    char tbuf[128];
    time_t tval;
    void * logprintfCookie;
}whois_session_params;

/* must be called BEFORE making any queries */
whois_session_params * w_init(void);
whois_session_params * w_reinit(whois_session_params * wsess);
void w_close(whois_session_params * wsess);

/* return the origin-asn according to the RADB in "3356" format */
int w_lookup_as(whois_session_params * wsess, char *);

/* return the origin-asn according to Cyrmu in "3356" format */
int w_lookup_as_cymru(whois_session_params * wsess, char *);

/* return the origin-asn according to the RIPE RIS in "3356" format */
int w_lookup_as_riswhois(whois_session_params * wsess, char *);

/* return the origin-asn according to pwhois in "3356" format */
int w_lookup_as_pwhois(whois_session_params * wsess, char *);

/* return the network name from the registrar in a string */
char *w_lookup_netname(whois_session_params * wsess, char *);

/* return the organization name from the registrar in a string */
char *w_lookup_orgname(whois_session_params * wsess, char *);

/* return a pointer to an ip_list_array (see above) containing
   an 'asn' to each corresponding 'ipaddr' according to Cymru   */
int w_lookup_as_cymru_bulk(whois_session_params * wsess, struct ip_list_array*);

/* return a pointer to an ip_list_array (see above) containing
   all ip_list_array vars to each corresponding 'ipaddr' according to pwhois   */
int w_lookup_all_pwhois_bulk(whois_session_params * wsess, struct ip_list_array*);
int w_lookup_all_pwhois_bulk_ext(whois_session_params * wsess, struct ext_ip_list_array *iplist);

/* return a pointer to an ip_list_array (see above) containing
   all ip_list_array vars to each corresponding 'ipaddr' according to RIS whois   */
int w_lookup_all_riswhois_bulk(whois_session_params * wsess, struct ip_list_array*);

int w_lookup_all_pwhois(whois_session_params * wsess, char *addr);
int w_lookup_all_riswhois(whois_session_params * wsess, char *addr);
#ifdef	__cplusplus
}
#endif

#endif
