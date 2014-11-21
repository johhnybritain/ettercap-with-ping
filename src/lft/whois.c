/*  
*  Handle communication with whois servers. 
*
*  This file is part of the Prefix WhoIs Project.
*  See http://pwhois.org
*
*  The full text of our legal notices is contained in the file called
*  COPYING, included with this Distribution.
* 
*  This software includes:
*       - simplified access to regular expressions
*       - tokenizer
*       - lookup functions for AS, NETNAME, ORGNAME 
*              - works with the following sources:
*         ARIN, RIPE, APNIC, RADB, CYMRU, PWHOIS, RISWHOIS
*              - will do recursive lookups
*       - convenient framework for further whois digging
*
*   To compile the standalone client:
*       cc -o whob whois.c -DSTANDALONE
*
*   
*   Portions (c) Victor Oppleman (lft@oppleman.com)
*   Portions (c) 2011 Markus Gothe <nietzsche@lysator.liu.se>
*   Portions (c) 2002 Ugen Antsilevitch (ugen@xonix.com)
*
*/

#include "lft_lib.h"

#define PORT_WHOIS  43

#if defined(WIN32) || defined(_WIN32)
#define read(a, b, c)   recv(a, b, c, 0)
#define write(a, b, c)  send(a, b, c, 0)
#define close(s) closesocket(s)
#define snprintf    _snprintf
#endif

#include "whois.h"

#if defined(BSD_IP_STACK)
#define pcap_snprintf    snprintf
#endif

#define LFT_STANDALONE 1

/*#define ASSERT(x)       if (!(x)) { fprintf(stderr, "Assertion ("#x") failed\n"); exit(EXIT_FAILURE); }*/

/* OPTIONS and variable initialization */

static char pwhois_server[] = "whois.pwhois.org";
static char radb_server[] = "whois.ra.net";
static char cymru_server[] = "whois.cymru.com";
static char arin_server[] = "whois.arin.net";
static char apnic_server[] = "whois.apnic.net";
static char ripe_server[] = "whois.ripe.net";
static char ripe_ris_server[] = "riswhois.ripe.net";

#ifdef LFT_STANDALONE
const char *version = "3.73";                    /* set version string for library and client */
const char *appname = "WhoB";            	    /* set application name */
static int go_interactive = 0;                  /* We'll wait on STDIN unless args suggest otherwise */
static int use_cymru = 0;                       /* Don't use Cymru by default */
static int use_riswhois = 0;                    /* Don't use RIPE NCC RIS by default */
static int display_orgname = 1;                 /* Display orgname by default */
static int display_aspath = 0;                  /* Don't display AS-PATH by default */
static int display_netname = 0;                 /* Don't display netname by default */
static int display_radb_as = 0;                 /* Don't display RADB Origin-AS by default */
static int show_routes_byasn = 0;               /* Don't show all advertisements by default */
static int show_networks_byasn = 0;             /* Don't show all networks by default */
static int show_contacts_byasn = 0;             /* Don't show all contact info by default */
static int show_routes_byprefix = 0;            /* Don't show all routes by prefix by default */
static int show_server_status = 0;              /* Don't show pwhois server status by default */
static int show_cache_date = 0;                 /* Don't show pwhois cache date by default */
static int read_from_file = 0;                  /* Don't read input from file by default */
static int riswhoisfromfile = 0;                /* Don't use riswhois by default for readfromfile */
static int cymrufromfile = 0;                   /* Don't use Cymru by default for readfromfile */
static int use_gigo = 1;                        /* Use GIGO feature by default */
static int use_stdin = 0;                       /* Don't use STDIN for bulk file input by default */
static const unsigned int max_hostname_input = 200;      /* Maximum length of input from user */
static const int max_lines = 2500;              /* Maximum lines to read from bulk file per query */
static const int line_size = 256;               /* Maximum line length */
static char hostname[256];
#endif

/* END of OPTIONS and variable initialization */
#if defined(WIN32) || defined(_WIN32)
char *
index(char *s, char c)
{
    char *t;
    if (!s)
        return NULL;
    
    for (t = s; *t; t++)
        if (*t == c) {
            return t;
        }
            
            /* Return terminating \0 if specifically requested */
            if (c == '\0')
                return t;
    
    return NULL;
}
#endif

#if defined(WIN32) || defined(_WIN32)
int
inet_aton(const char *cp, struct in_addr *pin)
{
    if (!pin)
        return -1;
    
    pin->s_addr = inet_addr(cp);
    return (pin->s_addr != -1) ? 1 : 0;
}
#endif

typedef struct token_s {
    char    *ptr;
} token_t;

static token_t *
tokens(char *buf, const char *sep)
{
    char *c, *c1;
    int size, cur;
    token_t *rt;
    
    if (!buf || !sep)
        return NULL;
    
    size = 1;
    for (c = buf; *c ; c++) 
        if (index(sep, *c)) {
            size++;
            while (*c && index(sep, *c)) 
                c++;
        }
            
            size++; /* for the NULL */
    
    if (!(rt = (token_t *)malloc(size * sizeof(token_t))))
        return NULL;
    
    memset(rt, 0, size * sizeof(token_t));
    
    rt[0].ptr = buf;
    cur = 0;
    
    for (c = buf; *c ; c++) {
        if (index(sep, *c)) {
            c1 = c;
            while (*c && index(sep, *c)) 
                c++;
            if (*c) 
                rt[++cur].ptr = c;
            
            *c1 = '\0';
        } 
    }
    
    rt[++cur].ptr = NULL;
    
    return rt;
}

typedef struct ip_blk_s {
    unsigned int    start;
    unsigned int    end;
} ip_blk_t;

static ip_blk_t *
w_blk2range(char *s_start, char *s_end)
{
    struct in_addr in;
    unsigned int s, e;
    ip_blk_t *r;
    
    if (!s_start || !s_end)
        return NULL;
    
    if (!inet_aton(s_start, &in))
        return NULL;
    
    s = ntohl(in.s_addr);
    
    if (!inet_aton(s_end, &in))
        return NULL;
    
    e = ntohl(in.s_addr);
    
    if (!(r = malloc(sizeof(ip_blk_t))))
        return NULL;
    
    r->start = s;
    r->end = e;
    return r;
}

static ip_blk_t *
w_mask2range(char *addr, char *mask)
{
    struct in_addr in;
    unsigned int s, m;
    ip_blk_t *r;
    
    if (!addr || !mask)
        return NULL;
    
    m = (unsigned int)strtoul(mask, (char **)NULL, 10);
    if (m > 32)
        return NULL;
    
    if (!inet_aton(addr, &in))
        return NULL;
    
    s = ntohl(in.s_addr);
    
    if (!(r = malloc(sizeof(ip_blk_t))))
        return NULL;
    
    r->start = s &~ (((unsigned)0xffffffff) >> m);
    r->end = s | (((unsigned)0xffffffff) >> m);
    return r;
}

static int rm_spaces(char* str)
{
    /* Remove spaces (isspace()) from anywhere within a string
    ONLY operates on a null-terminated (\0) string!  */
    
    int j = -1;
    unsigned int i;     
    
    if (!str) return 0;  
    
    for (i=0; i<=strlen(str); i++)
        if (!(isspace(*(str+i))))
            *(str+(++j)) = *(str+i);
        else
            continue;
    
    return 1;     
}

static char *match_prefix(const char *prefix, const char *target)
{
    /* Target will be something like "origin: AS22773" and prefix will be "origin:" and
    * we return a pointer to "AS22773" */
    while (*prefix) {
        if (tolower(*prefix) != tolower(*target))
            return NULL;
        prefix++;
        target++;
    }
    while (isspace(*target))
        target++;
    /* strip out the leading AS from the number */
    if (strncmp(target,"AS",2) == 0)
        target += 2;
    return strdup(target);
}

static ip_blk_t *match_iprange(char *target)
{
    /* matches something like "1.2.3.4-5.6.7.8" */
    char *pos, *dash, *beforedash;
    /* ip_blk_t *out; */
    
    while (isspace(*target))
        target++;
    pos = target;
    while (*pos && !isspace(*pos))
        pos++;
    
    beforedash = strdup(target);
    beforedash[pos-target] = 0;
    
    dash = strchr(target, '-');
    if (!dash)
        return NULL;
    dash++;
    while (isspace(*dash))
        dash++;
    
    return w_blk2range(beforedash, dash);
}

static ip_blk_t *match_ipprefix(char *target)
{
    /* matches something like 1.2.3.0/24 */
    char *slash, *pos;
    char *beforeslash;
    /* ip_blk_t *out; */
    
    while (isspace(*target))
        target++;
    pos = target;
    while (*pos && !isspace(*pos) && *pos != '/')
        pos++;
    beforeslash = strdup(target);
    beforeslash[pos - target] = 0;
    
    slash = strchr(target, '/');
    if (!slash) return NULL;
    
    slash++;
    
    return w_mask2range(beforeslash, slash);
}

static char *match_inparens(char *target)
{
    /* matches something like "    (HELLO)" and returns "HELLO" */
    char *end, *res;
    
    target = strchr(target, '(');
    if (!target)
        return NULL;
    
    target++;
    end = strchr(target, ')');
    if (!end)
        return NULL;
    
    res = strdup(target);
    res[end - target] = 0;
    return res;
}

static char *match_afterparens(char *target)
{
    /* matches something like "   (HELLO) xxx" and returns a pointer to "xxx" */
    target = strchr(target, '(');
    if (!target) return NULL;
    target = strchr(target, ')');
    if (!target) return NULL;
    target++;
    while(*target && isspace(*target)) target++;
    if (*target) return strdup(target);
    else return NULL;
}

whois_session_params *w_init(void)
{
    /* int e; */
    whois_session_params *wsess = (whois_session_params *)malloc(sizeof(whois_session_params));
    wsess->w_noisy = 0;	/* Don't show debug msgs by default */
    memset(&(wsess->pw_serv), 0, sizeof(wsess->pw_serv));
    wsess->consolidated_asn[0] = wsess->consolidated_asp[0] =
    wsess->consolidated_route[0] = wsess->consolidated_orgname[0] =
    wsess->consolidated_city[0] = wsess->consolidated_asorgname[0] =
    wsess->consolidated_region[0] = wsess->consolidated_country[0] =
    wsess->consolidated_netname[0] = '?';
    wsess->consolidated_asn[1] = wsess->consolidated_asp[1] =
    wsess->consolidated_route[1] = wsess->consolidated_orgname[1] =
    wsess->consolidated_netname[1] =0;
    memset(&wsess->tbuf, 0, sizeof(wsess->tbuf));
    wsess->logprintfCookie = 0;
    return wsess;
}

whois_session_params * w_reinit(whois_session_params * wsess)
{
    /* int e; */
    
    wsess->w_noisy = 0;                         /* Don't show debug msgs by default */
    memset(&(wsess->pw_serv), 0, sizeof(wsess->pw_serv));
    wsess->consolidated_asn[0] = wsess->consolidated_asp[0] =
    wsess->consolidated_route[0] = wsess->consolidated_orgname[0] =
    wsess->consolidated_city[0] = wsess->consolidated_asorgname[0] =
    wsess->consolidated_region[0] = wsess->consolidated_country[0] =
    wsess->consolidated_netname[0] = '?';
    wsess->consolidated_asn[1] = wsess->consolidated_asp[1] =
    wsess->consolidated_route[1] = wsess->consolidated_orgname[1] =
    wsess->consolidated_netname[1] = 0;
    memset(&wsess->tbuf, 0, sizeof(wsess->tbuf));
    wsess->logprintfCookie = 0;
    return wsess;
}
__inline__ void w_close(whois_session_params * wsess)
{
    free(wsess);
}

static char *
w_ask(const char *serv, const char *q, const char *port)
{
    int s;
    struct sockaddr_in sin4;
    struct hostent *hp;
    char *br;
    int q_s, br_s, cur, n, myport;
    char buf[128], *sendbuf;
#ifdef USE_WHOIS_TIMEOUT
#if defined(WIN32) || defined(_WIN32)
    int whreadtimeout = 20000;
#else
    struct timeval whreadtimeout;
    whreadtimeout.tv_sec = 20;
    whreadtimeout.tv_usec = 0;
#endif    
#endif    
    
    if (!serv || !q)
        return NULL;
    
    if (!(hp = gethostbyname(serv)))
        return NULL;
    
    sin4.sin_family = AF_INET;
    if (port) {
        if (!(myport = (int)strtol(port, (char **)NULL, 10))) 
            return NULL;
        sin4.sin_port = htons(myport);
    } else {
        sin4.sin_port = htons(PORT_WHOIS);
    }
    memcpy((void *)&sin4.sin_addr, hp->h_addr, hp->h_length);
    
    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
        return NULL;

#ifdef USE_WHOIS_TIMEOUT
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &whreadtimeout, sizeof(whreadtimeout));
#endif

    if (connect(s, (const struct sockaddr *)(const void *)&sin4, sizeof (sin4)) < 0) 
        return NULL;
    
    br_s = 512;
    if (!(br = (char *)malloc(br_s)))
        return NULL;
    
    	q_s = strlen(q);
	sendbuf = (char *)malloc(q_s+2);
	if(q[q_s-1]=='\r' || q[q_s-1]=='\n')
	{
		strncpy(sendbuf, q, q_s+1);
	}
	else
	{
		strncpy(sendbuf, q, q_s+1);
		sendbuf[q_s]='\n';
		q_s++;
		sendbuf[q_s]=0;
	}
    if (write(s, sendbuf, q_s) != q_s) /* || write(s, "\r\n", 2) != 2)*/
        return NULL;
    
    cur = 0;
    while ((n = read(s, buf, sizeof(buf))) > 0) {
        if ((cur + n) >= br_s) {
            br_s = br_s * 2;
            if (!(br = realloc(br, br_s)))
                return NULL;
        }
        strncpy((char *)&br[cur], buf, n);
        cur += n;   
    }
    br[cur] = 0;
    
    close(s);
    
    return br;
}

int 
w_lookup_all_pwhois(whois_session_params * wsess, char *addr)
{
    token_t *ls;
    char *serv, *reply;
    const char *format;
    int i;

    
    if (!addr)
        return -1;
    
    if (strlen(wsess->pw_serv) > 0)
        serv = wsess->pw_serv;
    else 
        serv = pwhois_server;
    
    reply = w_ask(serv, addr, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",serv);
            else
                fprintf(stderr,"No reply from %s.\n",serv);
        }
        return -1;
    }

    ls = tokens(reply, "\n");
    
    for (i = 0; ls[i].ptr; i++) {
        char *value = NULL;
        if ((value = match_prefix("origin-as:", ls[i].ptr))) {
            if (strncmp(wsess->consolidated_asn,"?",1) == 0) strncpy(wsess->consolidated_asn,value,255);
        } else
        if ((value = match_prefix("as-org-name:", ls[i].ptr))) {
            if (strncmp(wsess->consolidated_asorgname,"?",1) == 0) strncpy(wsess->consolidated_asorgname,value,255);
        } else
        if ((value = match_prefix("city:", ls[i].ptr))) {
            if (strncmp(wsess->consolidated_city,"?",1) == 0) strncpy(wsess->consolidated_city,value,255);
        } else
        if ((value = match_prefix("region:", ls[i].ptr))) {
            if (strncmp(wsess->consolidated_region,"?",1) == 0) strncpy(wsess->consolidated_region,value,255);
        } else
        if ((value = match_prefix("country:", ls[i].ptr))) {
            if (strncmp(wsess->consolidated_country,"?",1) == 0) strncpy(wsess->consolidated_country,value,255);
        } else
        if ((value = match_prefix("prefix:", ls[i].ptr))) {
            if (strncmp(wsess->consolidated_route,"?",1) == 0) strncpy(wsess->consolidated_route,value,255);
        } else
        if ((value = match_prefix("as-path:", ls[i].ptr))) {
            if (strncmp(wsess->consolidated_asp,"?",1) == 0) strncpy(wsess->consolidated_asp,value,255);
        } else
        if ((value = match_prefix("org-name:", ls[i].ptr))) {
            if (strncmp(wsess->consolidated_orgname,"?",1) == 0) strncpy(wsess->consolidated_orgname,value,255);
        } else
        if ((value = match_prefix("net-name:", ls[i].ptr))) {
            if (strncmp(wsess->consolidated_netname,"?",1) == 0) strncpy(wsess->consolidated_netname,value,255);
        } else
        if ((value = match_prefix("cache-date:", ls[i].ptr))) {
            if ((wsess->tval = atol(value)) != 0) {
                format = "%d-%b-%y %H:%M:%S %Z";
                (void)strftime(wsess->tbuf, sizeof(wsess->tbuf), format, localtime(&wsess->tval));
            }
        }
        if(value)
            free(value);
    }
    
    free(ls); 
    free(reply); 
    return 0;
}

int 
w_lookup_all_riswhois(whois_session_params * wsess, char *addr)
{
    token_t *ls=NULL;
    char *serv=NULL, *reply=NULL;
    const char *risopts = "-1 -M ";  /* 1 object/prefix, Most specific */
    char *risquery = malloc((strlen(risopts)* sizeof(char)) + (strlen(addr) * sizeof(char)) + 1);
    unsigned int i;
    
    if (!addr)
        return -1;
    
    /* prepare the text-string-based query */
    risquery[0]=0;
    strcat(risquery,risopts);
    strcat(risquery,addr);
    
    reply = w_ask(ripe_ris_server, risquery, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",serv);
            else
                fprintf(stderr,"No reply from %s.\n",serv);
        }
        return -1;
    }
    
    ls = tokens(reply, "\n");
    
    for (i = 0; ls[i].ptr; i++) {
        char *value = NULL;
        if ((value = match_prefix("origin:", ls[i].ptr))) {
            if (strncmp(wsess->consolidated_asn,"?",1) == 0) strncpy(wsess->consolidated_asn,value,255);
        } else
        if ((value = match_prefix("route:", ls[i].ptr))) {
            if (strncmp(wsess->consolidated_route,"?",1) == 0) strncpy(wsess->consolidated_route,value,255);
        } else
        if ((value = match_prefix("descr:", ls[i].ptr))) {
            if (strncmp(wsess->consolidated_orgname,"?",1) == 0) strncpy(wsess->consolidated_orgname,value,255);
            if (strncmp(wsess->consolidated_netname,"?",1) == 0) strncpy(wsess->consolidated_netname,value,255);
        }                                
        if(value)
            free(value);
    }
    
    free(ls); free(reply); free(risquery);
    return 0;
}

int
w_lookup_as_pwhois(whois_session_params * wsess, char *addr)
{
    token_t *ls;
    char *reply = NULL, *value = NULL;
    unsigned int i;
    int ans = 0;
    
    if (!addr)
        return 0;
    
    reply = w_ask(pwhois_server, addr, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",pwhois_server);
            else
                fprintf(stderr,"No reply from %s.\n",pwhois_server);
        }
        return 0;
    }
    ls = tokens(reply, "\n");
    
    for (i = 0; ls[i].ptr; i++) {
        if ((value = match_prefix("origin-as:", ls[i].ptr)))
            break;
    }
    
    free(ls); free(reply);
    
    if (!value)
        return 0;
    
    rm_spaces(value);
    
    for (i = 0; i < strlen(value); i++) {
        if (!isdigit(value[i])) {
            free(value);
            return 0;
        }
    }
    
    ans = strtol(value, (char **)NULL, 10);
    free(value);
    return ans;
}

int
w_lookup_as_riswhois(whois_session_params * wsess, char *addr)
{
    token_t *ls;
    char *reply = NULL, *value = NULL;
    const char *risopts = "-1 -M ";  /* 1 object/prefix, Most specific */
    char *risquery = malloc((strlen(risopts) * sizeof(char)) + (strlen(addr) * sizeof(char)) + 1);
    unsigned int i;
    int ans = 0;
    
    if (!addr)
        return 0;
    
    /* prepare the text-string-based query */
    risquery[0]=0;
    strcat(risquery,risopts);
    strcat(risquery,addr);
    
    reply = w_ask(ripe_ris_server, risquery, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",ripe_ris_server);
            else
                fprintf(stderr,"No reply from %s.\n",ripe_ris_server);
        }
        return 0;
    }
    ls = tokens(reply, "\n");
    
    for (i = 0; ls[i].ptr; i++) {
        if ((value = match_prefix("origin:", ls[i].ptr)))
            break;
    }
    
    free(ls);
    free(reply);
    free(risquery);
    
    if (!value)
        return 0;
    
    rm_spaces(value);
    
    for (i = 0; i < strlen(value); i++) {
        if (!isdigit(value[i])) {
            free(value);
            return 0;
        }
    }
    
    ans = atoi(value);
    free(value);
    return ans;
}

int
w_lookup_all_riswhois_bulk(whois_session_params * wsess, struct ip_list_array *iplist)
{
    
    token_t *responses=0;
    char *reply=0;
    const char *bulk_begin = "-k -1 -M\n";  /* Keepalive, 1 object/prefix, Most specific */
    const char *bulk_end = "-k";
    char *bulk_ip_query = malloc((strlen(bulk_begin) * sizeof(char)) + ((strlen(bulk_end)+1) * sizeof(char)) + (16 * (*iplist).numItems));
    int i = 0;
    unsigned int j = 0;
    int k = 0;
    int entity_id = 0;
    unsigned int until = 0;
    char *value = NULL;
    
    bulk_ip_query[0]=0;
    if (!iplist)
        return -1;
    
    /* clean up the response data set in case the caller doesn't (and we return error) */
    for (i = 0; i < (*iplist).numItems; i++) {
        (*iplist).asn[(i)] = 0;
        memset((*iplist).netName[i],0,sizeof((*iplist).netName[i]));
        memset((*iplist).orgName[i],0,sizeof((*iplist).orgName[i]));        
    }
    
    /* prepare the text-string-based query */
    strcat(bulk_ip_query,bulk_begin);
    for (i = 0; i < ((*iplist).numItems); i++) {
        strcat(bulk_ip_query,inet_ntoa((*iplist).ipaddr[i]));
        strcat(bulk_ip_query,"\n");
    }
    strcat(bulk_ip_query,bulk_end);
    
    reply = w_ask(ripe_ris_server, bulk_ip_query, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",ripe_ris_server);
            else
                fprintf(stderr,"No reply from %s.\n",ripe_ris_server);
        }
        /* clean up the response data set in case the caller doesn't */
        for (i = 0; i < (*iplist).numItems; i++)
            (*iplist).asn[(i)] = 0;
        return -1;
    }
    responses = tokens(reply, "\n");
    
    for (i = 0; responses[i].ptr; i++) {
        value = NULL;
        if ((value = match_prefix("origin:", responses[i].ptr)) != NULL) {
            if (k > 0) { entity_id++; k = 0; }
            rm_spaces(value);       /* strip out any spaces from the ASN */
            for (j = 0; j < strlen(value); j++) {
                if (!isdigit(value[j])) {
                    if (wsess->w_noisy)
                    {
                        if(wsess->logprintfCookie)
                            lft_printf(wsess->logprintfCookie,"Parse error at \'%c\': non-numeric value at position %d of %s).\n",value[i],i,value);
                        else
                            printf("Parse error at \'%c\': non-numeric value at position %d of %s).\n",value[i],i,value);
                    }
                    break;
                }
            }
            if(strtol(value, (char **) NULL, 10)) {
                (*iplist).asn[(entity_id)] = strtol(value, (char **)NULL, 10);
                k++; 
            } else if (wsess->w_noisy > 2)
            {
                if(wsess->logprintfCookie)
                    lft_printf(wsess->logprintfCookie,"Skipping additional object for same query.\n");
                else
                    fprintf(stderr,"Skipping additional object for same query.\n");
            }
        } else
        if ((value = match_prefix("descr:", responses[i].ptr))) {
            strncpy((*iplist).orgName[entity_id],value,100);
            /* yes, this is duplicated.  riswhois adds a netname attribute here, so we reuse 'descr' */
            for (until = 0; until < strlen(value); until++) {
                if (isspace(value[until]))
                    break;
            }
            strncpy((*iplist).netName[entity_id],value,(until));
            k++;
        } else
        if ((value = match_prefix("% ", responses[i].ptr)) != NULL) {
            if (i > 5 && k < 1) {   /* Weed out up to 5 leading lines from RIPE NCC RIS */
                if (wsess->w_noisy > 2)
                {
                    if(wsess->logprintfCookie)
                        lft_printf(wsess->logprintfCookie,"%% MATCHED on '%s'\n",responses[i].ptr);
                    else
                        printf("%% MATCHED on '%s'\n",responses[i].ptr);
                }
                /* (*iplist).asn[(entity_id)] = 0; */
                k++;
            } /* else printf("'%s'\n",responses[i].ptr); */
        } /* else printf("'%s'\n",responses[i].ptr); */
        if(value)
            free(value);
        if ((entity_id) >= (*iplist).numItems)
            break;
    }
    
    free(responses); free(reply); free(bulk_ip_query);
    
    return 0;
}

int
w_lookup_as(whois_session_params * wsess, char *addr)
{
    token_t *ls;
    ip_blk_t *a = NULL, *b = NULL;
    /* char *sa, *sb; */
    char *reply, *value = NULL;
    unsigned int i;
    int ans = 0;
    int use_this = 1;
    
    if (!addr)
        return 0;
    
    reply = w_ask(radb_server, addr, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",radb_server);
            else
                fprintf(stderr,"No reply from %s.\n",radb_server);
        }
        return 0;
    }
    ls = tokens(reply, "\n");
    
    for (i = 0; ls[i].ptr; i++) {
        value = NULL;
        if ((value = match_prefix("local-as:", ls[i].ptr)) != NULL) {
            break;
        } else
        if ((value = match_prefix("route:", ls[i].ptr)) != NULL) {
            a = match_ipprefix(value);
            
            if (b) {
                if (((b->end - b->start) > (a->end - a->start))) {
                    use_this = 1;
                    free(b);
                    b = a;
                    a = NULL;
                } else {
                    use_this = 0;
                    free(a);
                    a = NULL;
                }
            } else {
                use_this = 1;
                b = a;
                a = NULL;
            }
        } else
        if (use_this && (value = match_prefix("origin:", ls[i].ptr))) {
            break;
        }
        if(value != NULL)
            free(value);
    }
    
    free(ls);
    free(reply);
    if(b != NULL)
	free(b);
    
    if (!value)
        return 0;
    
    rm_spaces(value);
    
    for (i = 0; i < strlen(value); i++) {
        if (!isdigit(value[i])) {
            return 0;
        }
    }
    ans = strtol(value, (char **)NULL, 10);
    free(value);
    return ans;
}

int
w_lookup_as_cymru(whois_session_params * wsess, char *addr)
{
    /*
     *   Look up the ASN at the prefix-based Cymru whois server
     */
    token_t *ls;
    char *reply;
    unsigned int i;
    char value[6];
    memset(&value, 0, sizeof(value));
    
    if (!addr)
        return 0;
    
    reply = w_ask(cymru_server, addr, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",cymru_server);
            else
                fprintf(stderr,"No reply from %s.\n",cymru_server);
        }
        return 0;
    }
    ls = tokens(reply, "\n");
    
    /* Set i to 1 to skip the first/header line of reply from cymru */
    strncpy(value,ls[1].ptr,5);
    rm_spaces(value);       /* strip out any spaces from the ASN */
    
    for (i = 0; i < strlen(value); i++) {
        if (!isdigit(value[i])) {
            return 0;
        }
    }
    
    free(ls); 
    free(reply);
    return (strtol(value, (char **)NULL, 10));
}

int
w_lookup_as_cymru_bulk(whois_session_params * wsess, struct ip_list_array *iplist)
{
    
    token_t *responses;
    char *reply;
    const char *bulk_begin = "begin\n";
    const char *bulk_end = "end\n";
    char *bulk_ip_query = malloc((strlen(bulk_begin) * sizeof(char)) + (strlen(bulk_end)* sizeof(char)) + (16 * (*iplist).numItems));
    int i;
    unsigned int j;
    char value[6];
    memset(&value, 0, sizeof(value));
    
    bulk_ip_query[0]=0;
    if (!iplist)
        return -1;
    
    /* clean up the response data set in case the caller doesn't (and we return error) */
    for (i = 0; i < (*iplist).numItems; i++)
        (*iplist).asn[(i)] = 0; 
    
    /* prepare the text-string-based query */
    strcat(bulk_ip_query,bulk_begin);
    for (i = 0; i < ((*iplist).numItems); i++) {
        strcat(bulk_ip_query,inet_ntoa((*iplist).ipaddr[i]));
        strcat(bulk_ip_query,"\n");
    }
    strcat(bulk_ip_query,bulk_end);
    
    reply = w_ask(cymru_server, bulk_ip_query, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",cymru_server);
            else
                fprintf(stderr,"No reply from %s.\n",cymru_server);
        }
        return -1;
    }
    responses = tokens(reply, "\n");
    
    /* Set i to 1 to skip the first/header line of reply from cymru */
    for (i = 1; responses[i].ptr; i++) {
        strncpy(value,responses[i].ptr,5);
        rm_spaces(value);       /* strip out any spaces from the ASN */
        for (j = 0; j < strlen(value); j++) {
            if (!isdigit(value[j])) {
                if (wsess->w_noisy)
                {
                    if(wsess->logprintfCookie)
                        lft_printf(wsess->logprintfCookie,"Parse error at \'%c\': non-numeric value at position %d of %s).\n",value[i],i,value);
                    else
                        fprintf(stderr,"Parse error at \'%c\': non-numeric value at position %d of %s).\n",value[i],i,value);
                }
                break;
            }
        }
        if(strtol(value, (char **)NULL, 10)) { 
            (*iplist).asn[(i-1)] = strtol(value, (char **)NULL, 10);
        } else {
            (*iplist).asn[(i-1)] = 0;
        }
        if ((i+1) > (*iplist).numItems) 
            break;
    }
    
    free(responses); free(reply); free(bulk_ip_query); 
    
    return 0;
}

#ifdef LFT_STANDALONE
static int w_display_rvbyasn_pwhois(whois_session_params * wsess, char *asn)
{
    char *reply;
    const char *query_begin = "routeview source-as=";
    char *whob_query = NULL;
    char *serv;
    
    if (!asn) 
        return -1;
    
    if (strlen(wsess->pw_serv) > 0)
        serv = wsess->pw_serv;
    else
        serv = pwhois_server;
    
    whob_query = malloc( (strlen(appname) + strlen(version) + strlen(query_begin) + strlen(asn)) * sizeof(char) + 10);
    whob_query[0]=0;
    
    /* prepare the text-string-based query */
    strcat(whob_query,"app=\"");
    strcat(whob_query,appname);
    strcat(whob_query," ");
    strcat(whob_query,version);
    strcat(whob_query,"\" ");
    strcat(whob_query,query_begin);
    strcat(whob_query,asn);
    
    strcat(whob_query,"\n");
    
    reply = w_ask(serv, whob_query, NULL);
    if (!reply) {
        if (wsess->w_noisy) fprintf(stderr,"No reply from %s.\n",serv);
        return -1;
    }
    
    printf("%s",reply);
    
    free(reply); free(whob_query);
    
    return 0;
}

static int w_display_contactsbyasn_pwhois(whois_session_params * wsess, char *asn)
{
    char *reply;
    const char *query_begin = "registry source-as=";
    char *whob_query = NULL;
    char *serv;
    
    if (!asn) 
        return -1;
    
    if (strlen(wsess->pw_serv) > 0)
        serv = wsess->pw_serv;
    else
        serv = pwhois_server;
    
    whob_query = malloc( ((strlen(appname) + strlen(version) + strlen(query_begin) + strlen(asn)) * sizeof(char)) + 10);
    whob_query[0]=0;
    
    /* prepare the text-string-based query */
    strcat(whob_query,"app=\"");
    strcat(whob_query,appname);
    strcat(whob_query," ");
    strcat(whob_query,version);
    strcat(whob_query,"\" ");
    strcat(whob_query,query_begin);
    strcat(whob_query,asn);
    
    strcat(whob_query,"\n");
    
    reply = w_ask(serv, whob_query, NULL);
    if (!reply) {
        if (wsess->w_noisy) fprintf(stderr,"No reply from %s.\n",serv);
        return -1;
    }
    
    printf("%s",reply);
    
    free(reply); free(whob_query);
    
    return 0;
}

static int w_display_networksbyasn_pwhois(whois_session_params * wsess, char *asn)
{
    char *reply;
    const char *query_begin = "netblock source-as=";
    char *whob_query = NULL;
    char *serv;
    
    if (!asn) 
        return -1;
    
    if (strlen(wsess->pw_serv) > 0)
        serv = wsess->pw_serv;
    else
        serv = pwhois_server;
    
    whob_query =(char *)malloc(((strlen(appname) + strlen(version) + strlen(query_begin) + strlen(asn)) * sizeof(char)) + 10);
    whob_query[0]=0;

    /* prepare the text-string-based query */
    strcat(whob_query,"app=\"");
    strcat(whob_query,appname);
    strcat(whob_query," ");
    strcat(whob_query,version);
    strcat(whob_query,"\" ");
    strcat(whob_query,query_begin);
    strcat(whob_query,asn);
    
    strcat(whob_query,"\n");
    
    reply = w_ask(serv, whob_query, NULL);
    if (!reply) {
        if (wsess->w_noisy) fprintf(stderr,"No reply from %s.\n",serv);
        return -1;
    }
    
    printf("%s",reply);
    
    free(reply); free(whob_query);
    
    return 0;
}

static int w_display_rvbyprefix_pwhois(whois_session_params * wsess, char *prefix)
{
    char *reply;
    const char *query_begin = "routeview prefix=";
    char *whob_query = NULL;
    char *serv;
    
    if (!prefix) 
        return -1;
    
    if (strlen(wsess->pw_serv) > 0)
        serv = wsess->pw_serv;
    else
        serv = pwhois_server;
    
    whob_query = malloc(((strlen(appname) * sizeof(char))+10) + (strlen(version) * sizeof(char)) + (strlen(query_begin) * sizeof(char)) + (strlen(prefix))* sizeof(char));
    whob_query[0]=0;
    
    /* prepare the text-string-based query */
    strcat(whob_query,"app=\"");
    strcat(whob_query,appname);
    strcat(whob_query," ");
    strcat(whob_query,version);
    strcat(whob_query,"\" ");
    strcat(whob_query,query_begin);
    strcat(whob_query,prefix);
    
    strcat(whob_query,"\n");
    
    reply = w_ask(serv, whob_query, NULL);  
    if (!reply) {
        if (wsess->w_noisy) fprintf(stderr,"No reply from %s.\n",serv);
        return -1;
    }
    
    printf("%s",reply);
    
    free(reply); free(whob_query);
    
    return 0;
}

static int w_display_bulkfromfile_pwhois(whois_session_params * wsess, char *filespec)
{
    const char *query_begin = "begin\n";
    const char *query_end = "end\n";
    const char *appname_extras = "BULK_FILE";
    const char *format_instructions = "type=cymru\n";
    char *reply;
    char *serv;
    FILE *bulkFile;
    int num_lines = 0, i = 0;
    char *lines = malloc(line_size * max_lines);
    char *this_line = malloc(line_size);    
    size_t whob_query_len = ((strlen(appname) * sizeof(char) +10) + (strlen(appname_extras) * sizeof(char)) + (strlen(version) * sizeof(char))) + (strlen(query_begin) * sizeof(char)) + (strlen(format_instructions) * sizeof(char)) + (strlen(query_end) * sizeof(char)) + (line_size * max_lines);
    char *whob_query = (char *)malloc(whob_query_len);

    reply = NULL;
    *whob_query = '\0';
    
    if (!filespec) {
        fprintf(stderr,"You must specify a file to use (or '-' for stdin) for bulk query input.\n");
        free(lines);
	free(this_line);
	free(whob_query);
        exit(EXIT_FAILURE);
    }  
    
    if (!strncmp(filespec,"-",1) || use_stdin == 1) {
        bulkFile = stdin;
    } else 
        bulkFile = fopen(filespec, "r");
    
    if (!bulkFile) {
        fprintf(stderr,"%s: Unable to open \'%s\' for reading.\n",appname,filespec);
        free(lines);
	free(this_line); 
	free(whob_query);
        exit(EXIT_FAILURE);
    }
        
    if (strlen(wsess->pw_serv) > 0)
        serv = wsess->pw_serv;
    else
        serv = pwhois_server;
    
    while (!feof(bulkFile)) {
        
        if (num_lines >= max_lines && wsess->w_noisy >= 2)
            fprintf(stderr,"Processing next batch of %d beginning at line %d.\n",max_lines,(num_lines+1));
        
        memset(lines, 0, line_size * max_lines);
        memset(whob_query, 0, whob_query_len);
        
        for (i = 0; i < max_lines; i++) {
            
            if (fgets(this_line,line_size - 1,bulkFile)) {
                if (strncmp(this_line, "#", 1) && strncmp(this_line, ";", 1)) {
                    strcat(lines,this_line);
                    num_lines++;
                    if (wsess->w_noisy >= 4) 
                        fprintf(stderr,"Line %d: %s",num_lines,this_line);
                }
            } else if (feof(bulkFile)) {
                if (wsess->w_noisy >= 2) 
                    fprintf(stderr,"End of file reached after reading %d lines.\n",num_lines);
                break;
            } else if (ferror(bulkFile)) {
                if (wsess->w_noisy >= 1) 
                    fprintf(stderr,"Error in stream on line %d.\n",num_lines+1);
                break;
            }
            
        }
        
        /* prepare the text-string-based query */
        strcat(whob_query, query_begin);
        strcat(whob_query, "app=\"");
        strcat(whob_query, appname);
        strcat(whob_query, " ");
        strcat(whob_query, version);
        strcat(whob_query, " ");
        strcat(whob_query, appname_extras);
        strcat(whob_query, "\"\n");
        if (use_cymru) 
            strcat(whob_query, format_instructions);
        strcat(whob_query, lines);
        strcat(whob_query, query_end);
        
        reply = w_ask(serv, whob_query, NULL);
        if (!reply) {
            if (wsess->w_noisy)
		fprintf(stderr,"No reply from %s.\n",serv);
            free(this_line);
	    free(lines); 
	    free(whob_query);
	    free(reply);
            return -1;
        }
        
        printf("%s",reply);
        
    }
    
    free(this_line);
    free(lines);
    free(whob_query);
    free(reply);
    fclose(bulkFile);
    return 0;
}

static int w_display_bulkfromfile_riswhois(whois_session_params * wsess, char *filespec)
{
    const char *query_begin = "-k -1 -M\n";  /* Keepalive, 1 object/prefix, Most specific */
    const char *query_end = "-k";
    char *reply;
    char *serv;
    FILE *bulkFile;
    int num_lines = 0, i = 0;
    char *lines = (char *)malloc(line_size * max_lines);
    char *this_line = (char *)malloc(line_size);    
    size_t whob_query_len = 10 + (strlen(query_begin) * sizeof(char)) + (strlen(query_end) * sizeof(char)) + (line_size * max_lines);
    char *whob_query = (char *)malloc(whob_query_len);

    reply = NULL;
    *whob_query = '\0';
    
    if (!filespec) {
        fprintf(stderr,"You must specify a file to use (or '-' for stdin) for bulk query input.\n");
        free(lines);
        free(this_line);
        free(whob_query);
        exit(EXIT_FAILURE);
    }

    if (!strncmp(filespec,"-",1) || use_stdin == 1) {
        bulkFile = stdin;
    } else
        bulkFile = fopen(filespec, "r");
    
    if (!bulkFile) {
        fprintf(stderr,"%s: Unable to open \'%s\' for reading.\n",appname,filespec);
        free(lines);
	free(this_line);
	free(whob_query);
        exit(EXIT_FAILURE);
    }
    
    if (strlen(wsess->pw_serv) > 0)
        serv = wsess->pw_serv;
    else
        serv = ripe_ris_server;
    
    while (!feof(bulkFile)) {
        
        if (num_lines >= max_lines && wsess->w_noisy >= 2)
            fprintf(stderr,"Processing next batch of %d beginning at line %d.\n",max_lines,(num_lines+1));
        
        memset(lines, 0, line_size * max_lines);
        memset(whob_query, 0, whob_query_len);
        
        for (i = 0; i < max_lines; i++) {
            
            if (fgets(this_line,line_size - 1,bulkFile)) {
                if (strncmp(this_line, "#", 1) && strncmp(this_line, ";", 1)) {
                    strcat(lines,this_line);
                    num_lines++;
                    if (wsess->w_noisy >= 4) 
                        fprintf(stderr,"Line %d: %s",num_lines,this_line);
                }
            } else if(feof(bulkFile)) {
                if (wsess->w_noisy >= 2) 
                    fprintf(stderr,"End of file reached after reading %d lines.\n",num_lines);
                break;
            } else if (ferror(bulkFile)) {
                if (wsess->w_noisy >= 1) 
                    fprintf(stderr,"Error in stream on line %d.\n",num_lines+1);
                break;
            }
            
        }
        
        /* prepare the text-string-based query */
        strcat(whob_query, query_begin);
        strcat(whob_query, lines);
        strcat(whob_query, query_end);
        
        reply = w_ask(serv, whob_query, NULL);
        if (!reply) {
            if (wsess->w_noisy)
		fprintf(stderr,"No reply from %s.\n",serv);
            free(this_line);
	    free(lines);
	    free(whob_query);
	    free(reply);
            return -1;
        }
        
        printf("%s",reply);
        
    }
    
    free(this_line);
    free(lines);
    free(whob_query);
    free(reply);
    fclose(bulkFile);
    return 0;
}

static int w_display_bulkfromfile_cymru(whois_session_params * wsess, char *filespec)
{
    const char *query_begin = "begin\n";  
    const char *query_end = "end";
    char *reply;
    char *serv;
    FILE *bulkFile;
    int num_lines = 0, i = 0;
    char *lines = (char *)malloc(line_size * max_lines);
    char *this_line = (char *)malloc(line_size);    
    size_t whob_query_len = 10 + (strlen(query_begin) * sizeof(char)) + (strlen(query_end) * sizeof(char)) + (line_size * max_lines);
    char *whob_query = (char *)malloc(whob_query_len);
    
    reply = NULL;
    *whob_query = '\0';

    if (!filespec) {
        fprintf(stderr,"You must specify a file to use (or '-' for stdin) for bulk query input.\n");
        free(lines);
        free(this_line);
        free(whob_query);
        exit(EXIT_FAILURE);
    }

    if (!strncmp(filespec,"-",1) || use_stdin == 1) {
        bulkFile = stdin;
    } else
        bulkFile = fopen(filespec, "r");
    
    if (!bulkFile) {
        fprintf(stderr,"%s: Unable to open \'%s\' for reading.\n",appname,filespec);
        free(lines);
	free(this_line);
	free(whob_query);
        exit(EXIT_FAILURE);
    }
    
    if (strlen(wsess->pw_serv) > 0)
        serv = wsess->pw_serv;
    else
        serv = cymru_server;
    
    while (!feof(bulkFile)) {
        
        if (num_lines >= max_lines && wsess->w_noisy >= 2)
            fprintf(stderr,"Processing next batch of %d beginning at line %d.\n",max_lines,(num_lines+1));
        
        memset(lines, 0, line_size * max_lines);
        memset(whob_query, 0, whob_query_len);
        
        for (i = 0; i < max_lines; i++) {
            
            if (fgets(this_line, line_size - 1, bulkFile)) {
                if (strncmp(this_line, "#", 1) && strncmp(this_line, ";", 1)) {
                    strcat(lines, this_line);
                    num_lines++;
                    if (wsess->w_noisy >= 4) 
                        fprintf(stderr,"Line %d: %s",num_lines,this_line);
                }
            } else if(feof(bulkFile)) {
                if (wsess->w_noisy >= 2) 
                    fprintf(stderr,"End of file reached after reading %d lines.\n",num_lines);
                break;
            } else if(ferror(bulkFile)) {
                if (wsess->w_noisy >= 1) 
                    fprintf(stderr,"Error in stream on line %d.\n",num_lines+1);
                break;
            }
            
        }
        
        /* prepare the text-string-based query */
        strcat(whob_query, query_begin);
        strcat(whob_query, lines);
        strcat(whob_query, query_end);
        
        reply = w_ask(serv, whob_query, NULL);
        if (!reply) {
            if(wsess->w_noisy)
		fprintf(stderr,"No reply from %s.\n",serv);
            free(this_line); 
	    free(lines);
	    free(whob_query); 
	    free(reply);
            return -1;
        }
        
        printf("%s",reply);
        
    }
    
    free(this_line);
    free(lines);
    free(whob_query);
    free(reply);
    fclose(bulkFile);
    return 0;
}

static int w_display_pwhois_version(whois_session_params * wsess)
{
    char *reply;
    char *serv;
    
    if (strlen(wsess->pw_serv) > 0)
        serv = wsess->pw_serv;
    else
        serv = pwhois_server;
    
    if (wsess->w_noisy)
        fprintf(stderr,"Querying '%s' for version/status.\n",serv);
    
    reply = w_ask(serv, "version", NULL);
    if (!reply) {
        if(wsess->w_noisy)
		fprintf(stderr,"No reply from %s.\n",serv);
        return -1;
    }
    
    printf("%s",reply);
    
    free(reply);     
    return 0;
}

static int w_display_pwhois_gigo(whois_session_params * wsess, char *user_query)
{
    char *reply;
    char *serv;
    
    if (strlen(wsess->pw_serv) > 0)
        serv = wsess->pw_serv;
    else
        serv = pwhois_server;
    
    if (wsess->w_noisy)
        fprintf(stderr,"Querying '%s' for: '%s'\n",serv,user_query);
    
    reply = w_ask(serv, user_query, NULL);
    if (!reply) {
        if (wsess->w_noisy) fprintf(stderr,"No reply from %s.\n",serv);
        return -1;
    }
    
    printf("%s",reply);
    
    free(reply); 
    return 0;
}

#endif

int
w_lookup_all_pwhois_bulk(whois_session_params * wsess, struct ip_list_array *iplist)
{
    
    token_t *responses;
    char *reply;
    const char *bulk_begin = "begin\n";     
    const char *bulk_end = "end\n";         
    char *bulk_ip_query = NULL;
    int i = 0, k = 0, entity_id = 0;
    unsigned int j = 0;
    char *value = NULL;
    
    if (!iplist)
        return -1;
    
    if ((*iplist).application) {
        bulk_ip_query = (char *)malloc(((strlen((*iplist).application) * sizeof(char)) +10) + ((strlen(bulk_begin) + strlen(bulk_end) + 1) * sizeof(char)) + (16 * (*iplist).numItems));
    } else 
	bulk_ip_query = (char *)malloc(((strlen(appname) * sizeof(char)) +10) + ((strlen(version) + strlen(bulk_begin) + strlen(bulk_end) + 1) * sizeof(char)) + (16 * (*iplist).numItems));
    *bulk_ip_query = '\0';
    
    /* clean up the response data set in case the caller doesn't (and we return error) */
    for (i = 0; i < (*iplist).numItems; i++) {
        (*iplist).asn[(i)] = 0;
        memset((*iplist).netName[i],0,sizeof((*iplist).netName[i]));
        memset((*iplist).orgName[i],0,sizeof((*iplist).orgName[i]));        
    }
    
    /* prepare the text-string-based query */
    strcat(bulk_ip_query,bulk_begin);
    if ((*iplist).application) {
        strcat(bulk_ip_query, "app=\"");
        strcat(bulk_ip_query, (*iplist).application);
        strcat(bulk_ip_query, "\"\n");
    } else {
        strcat(bulk_ip_query, "app=\"");
        strcat(bulk_ip_query, appname);
        strcat(bulk_ip_query, " ");
        strcat(bulk_ip_query, version);
        strcat(bulk_ip_query, "\"\n");
    }
    
    for (i = 0; i < ((*iplist).numItems); i++) {
        strcat(bulk_ip_query, inet_ntoa((*iplist).ipaddr[i]));
        strcat(bulk_ip_query, "\n");
    }
    strcat(bulk_ip_query, bulk_end);
    
    reply = w_ask(pwhois_server, bulk_ip_query, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",pwhois_server);
            else
                fprintf(stderr,"No reply from %s.\n",pwhois_server);
        }
        /* clean up the response data set in case the caller doesn't */
        for (i = 0; i < (*iplist).numItems; i++) 
            (*iplist).asn[(i)] = 0;
        return -1;
    }
    responses = tokens(reply, "\n");
    
    for(i = 0; responses[i].ptr; i++){
        value = NULL;
        // printf("LINE %d: '%s'\n",i, responses[i].ptr);
        if((value = match_prefix("IP:", responses[i].ptr)) != NULL){
            /* if any keys matched, increment the id of the array */
            if(k > 0){
		entity_id++; 
		k = 0;
	    }
        } else
        if((value = match_prefix("origin-as:", responses[i].ptr)) != NULL) {
            rm_spaces(value);       /* strip out any spaces from the ASN */
            for(j = 0; j < strlen(value); j++) {
                if(!isdigit(value[j])){
                    if (wsess->w_noisy)
                    {
                        if(wsess->logprintfCookie)
                            lft_printf(wsess->logprintfCookie,"Parse error at \'%c\': non-numeric value at position %d of %s).\n",value[i],i,value);
                        else
                            fprintf(stderr,"Parse error at \'%c\': non-numeric value at position %d of %s).\n",value[i],i,value);
                    }
                    break;
                }
            }
            if ((int)strtol(value, (char **)NULL, 10)) {
                (*iplist).asn[(entity_id)] = strtol(value, (char **)NULL, 10);
                k++;
            } else {
                (*iplist).asn[(entity_id)] = 0;
                k++;
            }
        } else if ((value = match_prefix("org-name:", responses[i].ptr))) {
            strncpy((*iplist).orgName[entity_id],value,100);
            k++;
        } else if ((value = match_prefix("net-name:", responses[i].ptr))) {
            strncpy((*iplist).netName[entity_id],value,32);
            k++;
        }
        if(value)
            free(value);
        if ((entity_id+1) > (*iplist).numItems) 
            break;
    }
    
    free(responses);
    free(reply); 
    free(bulk_ip_query); 
    
    return 0;
}

int
w_lookup_all_pwhois_bulk_ext(whois_session_params * wsess, struct ext_ip_list_array *iplist)
{
    
    token_t *responses;
    char *reply;
    const char *bulk_begin = "begin\n";     
    const char *bulk_end = "end\n";         
    char *bulk_ip_query = NULL;
	int i=0;
	unsigned int j=0;
	int k=0;
    int pntcnt;
	int entity_id = 0;
    char *value = NULL;
    
    if (!iplist)
        return -1;
    iplist->geoavailable=0;

    if ((*iplist).application) {
        bulk_ip_query = malloc(((strlen((*iplist).application) * sizeof(char)) +10) + ((strlen(bulk_begin) + strlen(bulk_end) + 1) * sizeof(char)) + (16 * (*iplist).numItems));
    } else bulk_ip_query = malloc(((strlen(appname) * sizeof(char)) +10) + ((strlen(version) + strlen(bulk_begin) + strlen(bulk_end) + 1) * sizeof(char)) + (16 * (*iplist).numItems));
    bulk_ip_query[0]=0;
    
    /* clean up the response data set in case the caller doesn't (and we return error) */
    for (i = 0; i < (*iplist).numItems; i++) {
        (*iplist).asn[(i)] = 0;
        memset((*iplist).netName[i],0,sizeof((*iplist).netName[i]));
        memset((*iplist).orgName[i],0,sizeof((*iplist).orgName[i]));        
    }
    
    /* prepare the text-string-based query */
    strcat(bulk_ip_query,bulk_begin);
    if ((*iplist).application) {
        strcat(bulk_ip_query,"app=\"");
        strcat(bulk_ip_query,(*iplist).application);
        strcat(bulk_ip_query,"\"\n");
    } else {
        strcat(bulk_ip_query,"app=\"");
        strcat(bulk_ip_query,appname);
        strcat(bulk_ip_query," ");
        strcat(bulk_ip_query,version);
        strcat(bulk_ip_query,"\"\n");
    }
    
    for (i = 0; i < ((*iplist).numItems); i++) {
        strcat(bulk_ip_query,inet_ntoa((*iplist).ipaddr[i]));
        strcat(bulk_ip_query,"\n");
    }
    strcat(bulk_ip_query,bulk_end);
    
    reply = w_ask(pwhois_server, bulk_ip_query, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",pwhois_server);
            else
                fprintf(stderr,"No reply from %s.\n",pwhois_server);
        }
        /* clean up the response data set in case the caller doesn't */
        for (i = 0; i < (*iplist).numItems; i++) 
            (*iplist).asn[(i)] = 0;
        return -1;
    }
    responses = tokens(reply, "\n");
    
    for (i = 0; responses[i].ptr; i++) {
        value = NULL;
        // printf("LINE %d: '%s'\n",i, responses[i].ptr);
        if ((value = match_prefix("IP:", responses[i].ptr)) != NULL) {
            /* if any keys matched, increment the id of the array */
            if (k > 0) { entity_id++; k = 0; }
        } else
        if ((value = match_prefix("origin-as:", responses[i].ptr)) != NULL) {
            rm_spaces(value);       /* strip out any spaces from the ASN */
            for (j = 0; j < strlen(value); j++) {
                if (!isdigit(value[j])) {
                    if (wsess->w_noisy)
                    {
                        if(wsess->logprintfCookie)
                            lft_printf(wsess->logprintfCookie,"Parse error at \'%c\': non-numeric value at position %d of %s).\n",value[i],i,value);
                        else
                            fprintf(stderr,"Parse error at \'%c\': non-numeric value at position %d of %s).\n",value[i],i,value);
                    }
                    break;
                }
            }
            if(atoi(value)) {
                (*iplist).asn[(entity_id)] = atoi(value);
                k++;
            } else {
                (*iplist).asn[(entity_id)] = 0;
                k++;
            }
        } else if ((value = match_prefix("as-org-name-source:", responses[i].ptr))) {
            strncpy((*iplist).asOrgNameSource[entity_id],value,20);
            k++;
        } else if ((value = match_prefix("org-name-source:", responses[i].ptr))) {
            strncpy((*iplist).orgNameSource[entity_id],value,20);
            k++;
        } else if ((value = match_prefix("net-name-source:", responses[i].ptr))) {
            strncpy((*iplist).netNameSource[entity_id],value,20);
            k++;
        } else if ((value = match_prefix("prefix:", responses[i].ptr))) {
            strncpy((*iplist).prefix[entity_id],value,20);
            k++;
        } else if ((value = match_prefix("org-name:", responses[i].ptr))) {
            strncpy((*iplist).orgName[entity_id],value,100);
            k++;
        } else if ((value = match_prefix("net-name:", responses[i].ptr))) {
            strncpy((*iplist).netName[entity_id],value,32);
            k++;
        } else if ((value = match_prefix("longitude:", responses[i].ptr))) {
            rm_spaces(value);       /* strip out any spaces from the LONGITUDE */
            for (j = 0, pntcnt = 0; j < strlen(value); j++) {
                if(value[j]=='.')
                    pntcnt++;
                if (!isdigit(value[j]) && (value[j]!='.' || pntcnt>1)) {
                    if (wsess->w_noisy)
                    {
                        if(wsess->logprintfCookie)
                            lft_printf(wsess->logprintfCookie,"Parse error at \'%c\': can't parse value at position %d of %s).\n",value[i],i,value);
                        else
                            fprintf(stderr,"Parse error at \'%c\': can't parse value at position %d of %s).\n",value[i],i,value);
                    }
                    break;
                }
            }
            (*iplist).longitude[(entity_id)]=atof(value);
            iplist->geoavailable++;
            k++;
        } else if ((value = match_prefix("latitude:", responses[i].ptr))) {
            rm_spaces(value);       /* strip out any spaces from the LONGITUDE */
            for (j = 0, pntcnt = 0; j < strlen(value); j++) {
                if(value[j]=='.')
                    pntcnt++;
                if (!isdigit(value[j]) && (value[j]!='.' || pntcnt>1)) {
                    if (wsess->w_noisy)
                    {
                        if(wsess->logprintfCookie)
                            lft_printf(wsess->logprintfCookie,"Parse error at \'%c\': can't parse value at position %d of %s).\n",value[i],i,value);
                        else
                           fprintf(stderr,"Parse error at \'%c\': can't parse value at position %d of %s).\n",value[i],i,value);
                    }
                    break;
                }
            }
            (*iplist).latitude[(entity_id)]=atof(value);
            iplist->geoavailable++;
            k++;
        } else if ((value = match_prefix("city:", responses[i].ptr))) {
            strncpy((*iplist).city[entity_id],value,50);
            iplist->geoavailable++;
            k++;
        } else if ((value = match_prefix("country:", responses[i].ptr))) {
            strncpy((*iplist).country[entity_id],value,50);
            iplist->geoavailable++;
            k++;
        } else if ((value = match_prefix("region:", responses[i].ptr))) {
            strncpy((*iplist).state[entity_id],value,50);
            iplist->geoavailable++;
            k++;
        }
        if(value)
            free(value);
        if ((entity_id+1) > (*iplist).numItems) 
            break;
    }
    
    free(responses); free(reply); free(bulk_ip_query); 
    
    return 0;
}

static char *
w_lookup_netname_other(whois_session_params * wsess, char *addr, char *serv)
{
    token_t *ls;
    ip_blk_t *a = NULL, *b = NULL;
    char *reply, *ans = NULL;
    int i;
    int use_this = 1;
    
    if (!addr || !serv)
        return NULL;
    
    reply = w_ask(serv, addr, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",serv);
            else
                fprintf(stderr,"No reply from %s.\n",serv);
        }
        return NULL;
    }
    ls = tokens(reply, "\n");
    
    for (i = 0; ls[i].ptr; i++) {
        char *value=NULL;
        if ((value = match_prefix("inetnum:", ls[i].ptr))) {
            a = match_ipprefix(value);
            
            if (b) {
                if (((b->end - b->start) > (a->end - a->start))) {
                    use_this = 1;
                    free(b);
                    b = a;
                    a = NULL;
                } else {
                    use_this = 0;
                    free(a);
                    a = NULL;
                }
            } else {
                use_this = 1;
                b = a;
                a = NULL;
            }
            free(value);
        } else
        if (use_this && (value = match_prefix("netname:", ls[i].ptr))) {
            if (ans)
                free(ans);
            ans = value;
        } 
    }
    
    free(ls); free(reply); if (b) free(b);
    return ans;
}

char *
w_lookup_netname(whois_session_params * wsess, char *addr)
{
    token_t *ls;
    ip_blk_t *a = NULL, *b = NULL;
    char *na = NULL, *nb = NULL;
    char *reply, *ans = NULL;
    int i;
    int have_new, have_old;
    
    if (!addr)
        return NULL;
    
    reply = w_ask(arin_server, addr, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",arin_server);
            else
                fprintf(stderr,"No reply from %s.\n",arin_server);
        }
        return NULL;
    }
    ls = tokens(reply, "\n");
    
    ans = NULL;
    for (i = 0; ls[i].ptr; i++) {
        char *value;
        if ((value = match_prefix("netname:", ls[i].ptr))) {
            ans = value;
            break;
        }
    }
    
    if (!ans) {
        
        for (i = 0; ls[i].ptr; i++) {
            char *value;
            if ((value = match_inparens(ls[i].ptr))) {
                char *after = match_afterparens(ls[i].ptr);
                if (after) {
                    na = value;
                    a = match_iprange(after);
                } else {
                    na = value;
                    if (ls[i+1].ptr && (a = match_iprange(ls[i+1].ptr))) {
                        /* successful match */
                    } else { /* Bad format */
                        free(na); na = NULL;
                        continue;
                    }
                }
            }
            
            have_new = (na && a);
            have_old = (nb && b);
            
            if (have_new) {
                if (have_old) {
                    if (((b->end - b->start) > (a->end - a->start))) {
                        /* keep new, discard old */
                        free(nb); free(b);
                        nb = na; na = NULL;
                        b = a; a = NULL;
                    } else { /* keep old, discard new */
                        free(na); free(a);
                        na = NULL;
                        a = NULL;
                    }
                } else { /* nothing old, save new */
                    nb = na; na = NULL;
                    b = a; a = NULL;
                }
            }
        } /* loop */

    if (na) free(na);
    if (a) free(a);
    if (b) free(b);
    free(ls); free(reply);
    if (!nb)
        return NULL;

    /* Add "!" to the beginning of the question */
    na = malloc(strlen(nb) + 2);
    strcpy(&na[1], nb);
    na[0] = '!';
    free(nb);

    reply = w_ask(arin_server, na, NULL);
    free(na);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",arin_server);
            else
                fprintf(stderr,"No reply from %s.\n",arin_server);
        }
        return NULL;
    }

    ls = tokens(reply, "\n");

    }
    for (i = 0; ls[i].ptr; i++) {
        char *value;
        if ((value = match_prefix("netname:", ls[i].ptr))) {
            ans = value;
            break;
        }
    }

    free(ls); free(reply); 

    {
        char *other = NULL;
        if (ans && strstr(ans, "RIPE")) {
            other = w_lookup_netname_other(wsess, addr, ripe_server);
        }
        
        if (ans && !strncmp(ans, "APNIC", 5)) {
            other = w_lookup_netname_other(wsess, addr, apnic_server);
        }
        
        if (other) {
            char *together = malloc(strlen(ans) + strlen(other) + 2);
            together[0]=0;
            strcpy(together, ans);
            strcat(together, "/");
            strcat(together, other);
            free(ans);
            ans = together;
        }
    }

    return ans;
}

static char *
w_lookup_orgname_other(whois_session_params * wsess, char *addr, char *serv)
{
    token_t *ls;
    ip_blk_t *a = NULL, *b = NULL;
    char *reply, *ans = NULL;
    int i;
    int use_this = 1;
    
    if (!addr || !serv)
        return NULL;
    
    reply = w_ask(serv, addr, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",serv);
            else
                fprintf(stderr,"No reply from %s.\n",serv);
        }
        return NULL;
    }
    ls = tokens(reply, "\n");
    
    for (i = 0; ls[i].ptr; i++) {
        char *value=NULL;
        if ((value = match_prefix("inetnum:", ls[i].ptr))) {
            a = match_ipprefix(value);
            
            if (b) {
                if (((b->end - b->start) > (a->end - a->start))) {
                    use_this = 1;
                    free(b);
                    b = a;
                    a = NULL;
                } else {
                    use_this = 0;
                    free(a);
                    a = NULL;
                }
            } else {
                use_this = 1;
                b = a;
                a = NULL;
            }
            free(value);
        }else
        if (use_this && (value = match_prefix("orgname:", ls[i].ptr))) {
            if (ans)
                free(ans);
            ans = value;
        }
    }
    
    if (!ans) {
        for (i = 0; ls[i].ptr; i++) {
            char *value;
            if (use_this && (value = match_prefix("descr:", ls[i].ptr))) {
                if (ans)
                    free(ans);
                ans = value;
                break;
            }
        }
    }
    
    free(ls); free(reply); if (b) free(b);
    return ans;
}

char *
w_lookup_orgname(whois_session_params * wsess, char *addr)
{
    token_t *ls;
    ip_blk_t *a = NULL, *b = NULL;
    char *na = NULL, *nb = NULL;
    char *reply, *ans = NULL;
    int i;
    int have_new, have_old;
    
    if (!addr)
        return NULL;
    
    reply = w_ask(arin_server, addr, NULL);
    if (!reply) {
        if (wsess->w_noisy)
        {
            if(wsess->logprintfCookie)
                lft_printf(wsess->logprintfCookie,"No reply from %s.\n",arin_server);
            else
                fprintf(stderr,"No reply from %s.\n",arin_server);
        }
        return NULL;
    }
    ls = tokens(reply, "\n");
    
    for (i = 0; ls[i].ptr; i++) {
        char *value;
        if ((value = match_prefix("netname:", ls[i].ptr))) {
            ans = value;
            break;
        } 
    }
    
    if (!ans) {
        
        for (i = 0; ls[i].ptr; i++) {
            char *value;
            if ((value = match_inparens(ls[i].ptr))) {
                char *after = match_afterparens(ls[i].ptr);
                if (after) {
                    na = value;
                    a = match_iprange(after);
                } else {
                    na = value;
                    if (ls[i+1].ptr && (a = match_iprange(ls[i+1].ptr))) {
                        /* successful match */
                    } else { /* Bad format */
                        free(na); na = NULL;
                        continue;
                    }
                }
            }
            
            have_new = (na && a);
            have_old = (nb && b);
            
            if (have_new) {
                if (have_old) {
                    if (((b->end - b->start) > (a->end - a->start))) {
                        /* keep new, discard old */
                        free(nb); free(b);
                        nb = na; na = NULL;
                        b = a; a = NULL;
                    } else { /* keep old, discard new */
                        free(na); free(a);
                        na = NULL;
                        a = NULL;
                    }
                } else { /* nothing old, save new */
                    nb = na; na = NULL;
                    b = a; a = NULL;
                }
            }
        } /* loop */

        if (na) free(na);
        if (a) free(a);
        if (b) free(b);
        free(ls); free(reply);
        if (!nb)
            return NULL;

        /* Add "!" to the beginning of the question */
        na = malloc(strlen(nb) + 2);
        strcpy(&na[1], nb);
        na[0] = '!';
        free(nb);

        reply = w_ask(arin_server, na, NULL);
        free(na);
        if (!reply) {
            if (wsess->w_noisy)
            {
                if(wsess->logprintfCookie)
                    lft_printf(wsess->logprintfCookie,"No reply from %s.\n",arin_server);
                else
                    fprintf(stderr,"No reply from %s.\n",arin_server);
            }
            return NULL;
        }

        ls = tokens(reply, "\n");

    }
        for (i = 0; ls[i].ptr; i++) {
            char *value;
            if ((value = match_prefix("orgname:", ls[i].ptr))) {
                if(ans)
                    free(ans);
                ans = value;
                break;
            }
        }

        free(ls); free(reply);

        {
            char *other = NULL;
            if (ans && strstr(ans, "RIPE")) {
                other = w_lookup_orgname_other(wsess, addr, ripe_server);
            }
            
            if (ans && (!strncmp(ans, "APNIC", 5) || strstr(ans, "Asia Pacific Net") )) {
                other = w_lookup_orgname_other(wsess, addr, apnic_server);
            }
            
            if (other) {
                /*            char *together = malloc(strlen(ans) + strlen(other) + 4);
                strcpy(together, other);
                strcat(together, " (");
                strcat(together, ans);
                strcat(together, ")");
                */
                free(ans);
                ans = other;
            }
        }

        return ans;
}

#ifdef LFT_STANDALONE
/*---------------------------------------------------------------------------*/
void lft_printf(lft_session_params * sess, const char *templ, ...)
{
  va_list ap;
  char buf[1024];

  (void)sess;

  va_start (ap, templ);
  vsprintf(buf, templ, ap);
  va_end (ap);
  printf("%s",buf);
}
/*---------------------------------------------------------------------------*/
static void
usage (char *prog)
{
    fprintf (stderr,
             "\nWhoB - version %s\n\n"
             "     - a likable whois client from the Prefix WhoIs project\n"
             "                                visit http://www.pwhois.org\n"
             "\nUsage: %s [-g] [<options>] <target>\n"
             "\nMainstream Options:\n"
             "  -g         Disable GIGO mode; enable other options then submit query\n"
             "  -R         Display the Origin-AS on file at the RADB/IRR also\n"
             "  -p         Display the AS-Path learned by the pWhoIs server (pWhoIs-only)\n"
             "  -n         Display the network name on file at the registrar\n"
             "  -t         Display the date the route was last updated (pWhoIs-only)\n"
             "  -u         Display the date the route was last updated in GMT (pWhoIs-only)\n"
             "  -o         Disable display of the organization\'s name on file at the registrar\n"
             "\nAdvanced Options:\n"             
             "  -h host    Specify your own pWhoIs-compatible server to query\n"
             "  -f file    Read from 'file' (or '-' as stdin) as bulk input to pWhoIs\n"
             "  -c         Use Cymru\'s whois server instead of pWhoIs\n"
             "  -r         Use RIPE NCC\'s RIS whois server instead of pWhoIs\n"
             "\nPrefix WhoIs Advanced Options:\n"
             "  -a         Display all routes announced by the target ASN (pWhoIs-only)\n"
             "  -P         Display all routes respective to a target prefix (pWhoIs-only)\n"
             "  -N         Display all networks registered to the target ASN (pWhoIs-only)\n"
             "  -O         Display organizational contact info for the target ASN (pWhoIs-only)\n"
             "\nVerbosity Options and Status:\n"
             "  -s         Display the version and status of the pWhoIs server (pWhoIs-only)\n"
             "  -V         Display verbose/debug output.  Use more \'V\'s for additional detail\n"
             "  -v         Display WhoB\'s version information and exit\n"  
             "\n"
             ,version,prog);
    fprintf(stderr,"Example:     %s -gnp 1.2.3.4\n",prog);
    fprintf(stderr,"Returns:     IP Address | ASN-by-prefix (prefix) | AS-Path | NetName | OrgName\n\n"); 
    exit(EXIT_FAILURE);
}

static void
show_startup_msgs (whois_session_params * wsess)
{
    if (wsess->w_noisy) {
        fprintf(stderr,"WhoB version %s firing up...",version);
        if (wsess->w_noisy > 1) fprintf(stderr," (verbosity level %d)\n",wsess->w_noisy); else printf ("\n");
        if (wsess->w_noisy > 1) {
            fprintf(stderr,"Data sources:");
            if ((strlen(wsess->pw_serv) > 0) && (!use_cymru || read_from_file)) fprintf(stderr," %s (pWhoIs)",wsess->pw_serv); 
            else if ((!use_cymru || read_from_file) && !use_riswhois) fprintf(stderr," %s (pWhoIs)", pwhois_server);
            else if (!use_cymru) fprintf(stderr," %s (RIPE NCC)", ripe_ris_server);
            if (use_cymru && !read_from_file) fprintf(stderr," %s (Cymru)",cymru_server);
            if (display_radb_as) fprintf(stderr,", %s (RADB)",radb_server);
            fprintf(stderr,".\n");
            if (read_from_file) {
                if (cymrufromfile) fprintf(stderr,"Using Cymru for bulk file resolution.\n");
                else if (riswhoisfromfile) fprintf(stderr,"Using RIPE NCC for bulk file resolution.\n");
                else fprintf(stderr,"Using Prefix WhoIs for bulk file resolution.\n");
            }
        }
        if (show_routes_byprefix == 1 && show_routes_byasn == 1) {
            fprintf(stderr,"You may only perform routeviews one at a time.  Using by-ASN.\n");
            show_routes_byprefix = 0;
        } 
    }
}

int main(int ac, char **av)
{
    struct hostent *he, *pwhost;
    char *addr = NULL;
    struct in_addr in, pws;
    int ch;
    int user_asn = 0;
    char user_asn_buf[10];
    whois_session_params * wsess;
    
    memset(&hostname, 0, sizeof(hostname));
    
    wsess = w_init();
    setbuf(stdout, NULL);
        
    while ((ch = getopt (ac, av, "aCcfgNnOopPRrstuVvh:w:")) != EOF)
        switch (ch) {
            case 'a':
                use_gigo = 0;
                show_routes_byasn = 1;
                go_interactive = 1;
                break;
            case 'N':
                use_gigo = 0;
                show_networks_byasn = 1;
                go_interactive = 1;
                break;
            case 'O':
                use_gigo = 0;
                show_contacts_byasn = 1;
                go_interactive = 1;
                break;
            case 's':
                use_gigo = 0;
                show_server_status = 1;
                go_interactive = 1;
                break;
            case 'P':
                use_gigo = 0;
                show_routes_byprefix = 1;
                go_interactive = 1;
                break;
            case 'v':
                usage(av[0]);
                break;
            case 'u':   /* show all times in UTC */
#if defined(sun)
                if(putenv("TZ=GMT0") == -1) {
                    fprintf(stderr, "%s: Unable to set TZ to UTC.",appname);
                }                
#else
#if !defined(WIN32) && !defined(_WIN32)
                if (setenv("TZ", "GMT0", 1) == -1) {
                    fprintf(stderr, "%s: Unable to set TZ to UTC.",appname);
                }
#endif
#endif
                show_cache_date = 1;
                break;
            case 't':
                show_cache_date = 1;
                break;
            case 'w':
                if (strlen(optarg) > max_hostname_input) {
                    fprintf(stderr,"Sorry, the server name you supplied was unreasonably long.\n");
                    exit(EXIT_FAILURE);
                }
                if (inet_aton(optarg, &pws)) {
                    strncpy(wsess->pw_serv, optarg, strlen(optarg));
                } else {
                    if (!(pwhost = gethostbyname(optarg))) {
                        fprintf(stderr,"Sorry, I cannot resolve \'%s\' to use as your pWhoIs server.\n", optarg);
                        exit(EXIT_FAILURE);
                    }
                    memcpy(&pws, pwhost->h_addr, pwhost->h_length);
                    strncpy(wsess->pw_serv,inet_ntoa(pws),strlen(inet_ntoa(pws)));
                }
                break;
            case 'h':
                if (strlen(optarg) > max_hostname_input) {
                    fprintf(stderr,"Sorry, the server name you supplied was unreasonably long.\n");
                    exit(EXIT_FAILURE);
                }
                if (inet_aton(optarg, &pws)) {
                    strncpy(wsess->pw_serv,optarg,strlen(optarg));
                } else {
                    if (!(pwhost = gethostbyname(optarg))) {
                        fprintf(stderr,"Sorry, I cannot resolve \'%s\' to use as your pWhoIs server.\n", optarg);
                        exit(EXIT_FAILURE);
                    }
                    memcpy(&pws, pwhost->h_addr, pwhost->h_length);
                    strncpy(wsess->pw_serv,inet_ntoa(pws),strlen(inet_ntoa(pws)));
                }
                break;
            case 'c':
                use_cymru = 1;
                /* cymrufromfile = 1; */      /* Use pwhois Cymru compatibility mode by default */
                break;
            case 'C':
                use_cymru = 1;
                cymrufromfile = 1;
                break;
            case 'n':
                display_netname = 1;
                go_interactive = 1;
                break;
            case 'r':
                use_riswhois = 1;
                riswhoisfromfile = 1;
                break;
            case 'R':
                display_radb_as = 1;
                go_interactive = 1;
                break;
            case 'o':
                display_orgname = 0;
                go_interactive = 1;
                break;
            case 'p':
                display_aspath = 1;
                go_interactive = 1;
                break;
            case 'f':
                use_gigo = 0;
                read_from_file = 1;
                break;
            case 'V':
                wsess->w_noisy++;
                break;
            case 'g':
                use_gigo = 0;
                go_interactive = 1;
                break;
            default:
                usage (av[0]);
        }

    /* Catch hostname input without any arguments */
    if ((ac - optind) > 0) 
        go_interactive = 1;
                            
    if (go_interactive > 0) {
    /*  Quickly check stdin for input to avoid David having to type   */
    /*  '-f -' to pipe into to whob, even if it has args :-)          */
        fd_set rfds;
        struct timeval timev;
        int selretval;
     
        /* Watch stdin (fd 0) briefly for input. */
        FD_ZERO(&rfds);
        FD_SET(0, &rfds);
        
        timev.tv_sec = 0;
        timev.tv_usec = 100;
     
        selretval = select(1, &rfds, NULL, NULL, &timev);
     
        if (selretval) {
            /* There's input in them there hills, treat it as the input file */
            use_gigo = 0; 
            read_from_file = 1;
            use_stdin = 1;
        } 
        /*
          else
            if (wsess->w_noisy) fprintf(stderr,"No input found on stdin.\n");
        */
    } else if (read_from_file < 1) {
        /* No indication we should be interactive based on arguments, so wait for STDIN */
        use_gigo = 0;
        read_from_file = 1;
        use_stdin = 1;
    }
            
    if (((ac - optind) < 1) && (show_server_status != 1) && (go_interactive > 0))
        usage (av[0]);
        
    /* Show the verbose startup information if verbosity is enabled/requested */
    show_startup_msgs(wsess);
                    
    if (show_server_status == 1) {
        w_display_pwhois_version(wsess);
        exit(EXIT_FAILURE);
    } else if ((read_from_file > 0 && use_stdin < 1) || go_interactive > 0) { 
    
        if (strlen(av[optind]) > max_hostname_input) {        
            fprintf(stderr,"Sorry, the subject name you supplied was unreasonably long.\n");
            exit(EXIT_FAILURE);
        } else {
            strncpy(hostname,av[optind],strlen(av[optind]));
            optind++;
        }
    }
    
    if (read_from_file) {
        if (riswhoisfromfile) 
            w_display_bulkfromfile_riswhois(wsess, hostname);
        else if (cymrufromfile)
            w_display_bulkfromfile_cymru(wsess, hostname);
        else 
            w_display_bulkfromfile_pwhois(wsess, hostname);
        exit(EXIT_SUCCESS);
    }
    
    if (use_gigo > 0) {
        w_display_pwhois_gigo(wsess, hostname);
        printf("w_display_pwhois_gigo DONE!");
        exit(EXIT_SUCCESS);
    }
    
    if ((show_routes_byasn || show_contacts_byasn || show_networks_byasn) && (strlen(hostname) <= 10) && atoi(hostname)) {
        user_asn = atoi(hostname);
        if (wsess->w_noisy > 1) fprintf(stderr,"Using user-supplied ASN %d for lookup.\n",user_asn);
    } else if (show_routes_byprefix == 1) {
        printf("Displaying all routes for prefix %s.\n",hostname);
    } else {
        
        if (inet_aton(hostname, &in)) {
            addr = hostname;
        } else {
            if (!(he = gethostbyname(hostname))) {
                fprintf(stderr,"Sorry, I cannot resolve \'%s\'\n", hostname);
                exit(EXIT_FAILURE);
            }
            memcpy(&in, he->h_addr, he->h_length);
            addr = inet_ntoa(in);
        }
    }
    
    if (show_routes_byasn) {
        if (user_asn > 0) {
            printf("Displaying all routes whose Origin-AS is %d.\n", user_asn);
            snprintf(user_asn_buf,9,"%d",user_asn);
            w_display_rvbyasn_pwhois(wsess, user_asn_buf);
        } else {
            w_lookup_all_pwhois(wsess, addr);
            if (atoi(wsess->consolidated_asn)) {
                printf("Displaying all routes whose Origin-AS is %s.\n", wsess->consolidated_asn);
                w_display_rvbyasn_pwhois(wsess, wsess->consolidated_asn);
            } else {
                printf("Sorry, unable to resolve the ASN for %s (%s) at this time.\n",hostname,addr);
            }
        }
    } else if (show_networks_byasn) {
        if (user_asn > 0) {
            printf("Displaying all networks registered to the Origin-AS %d.\n", user_asn);
            snprintf(user_asn_buf,9,"%d",user_asn);
            w_display_networksbyasn_pwhois(wsess, user_asn_buf);
        } else {
            w_lookup_all_pwhois(wsess, addr);
            if (atoi(wsess->consolidated_asn)) {
                printf("Displaying all networks registered to the Origin-AS %s.\n", wsess->consolidated_asn);
                w_display_networksbyasn_pwhois(wsess, wsess->consolidated_asn);
            } else {
                printf("Sorry, unable to resolve the ASN for %s (%s) at this time.\n",hostname,addr);
            }
        }    
    } else if (show_contacts_byasn) {
        if (user_asn > 0) {
            printf("Displaying all contact info on file for Origin-AS %d.\n", user_asn);
            snprintf(user_asn_buf,9,"%d",user_asn);
            w_display_contactsbyasn_pwhois(wsess, user_asn_buf);
        } else {
            w_lookup_all_pwhois(wsess, addr);
            if (atoi(wsess->consolidated_asn)) {
                printf("Displaying all contact info on file for Origin-AS %s.\n", wsess->consolidated_asn);
                w_display_contactsbyasn_pwhois(wsess, wsess->consolidated_asn);
            } else {
                printf("Unable to resolve the ASN for %s (%s) at this time.\n",hostname,addr);
            }
        }                
    } else if (show_routes_byprefix) {
        w_display_rvbyprefix_pwhois(wsess, hostname);
    } else {
        
        printf("%s | Searching...", addr);
        
        if (use_cymru) {
            printf("\b\b\b\b\b\b\b\b\b\b\b\b");
            printf("origin-as %d ", w_lookup_as_cymru(wsess, addr));
        } else if (use_riswhois) {
            w_lookup_all_riswhois(wsess, addr);
            printf("\b\b\b\b\b\b\b\b\b\b\b\b");
            printf("origin-as %s (%s) ", wsess->consolidated_asn, wsess->consolidated_route);
        } else {
            w_lookup_all_pwhois(wsess, addr);
            printf("\b\b\b\b\b\b\b\b\b\b\b\b");
            printf("origin-as %s (%s) ", wsess->consolidated_asn, wsess->consolidated_route);
            if (show_cache_date && (strlen(wsess->tbuf) > 0))
                printf("| %s ", wsess->tbuf);
        }
        
        if (display_radb_as) 
            printf("| radb-as %d ", w_lookup_as(wsess, addr));
        
        if ((display_aspath) && (!use_cymru) && (!use_riswhois))
            printf("| as-path %s ", wsess->consolidated_asp);
        
        if (display_netname) {
            if (use_cymru) {
                printf("| %s ", w_lookup_netname(wsess, addr));
            } else if (use_riswhois) {
                if (!display_orgname) 
                    printf("| %s ", wsess->consolidated_netname);
            } else {
                printf("| %s ", wsess->consolidated_netname);
            }
        }
        
        if (display_orgname) {
            if (use_cymru) {
                printf("| %s ", w_lookup_orgname(wsess, addr));
            } else {
                printf("| %s ", wsess->consolidated_orgname);
            }
        }
        printf("\n");
    }
    w_close(wsess);

    exit(EXIT_SUCCESS);
}
#endif

