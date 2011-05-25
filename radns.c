/*
 * radns - Router Advertisement DNS
 *
 * Small program to listen for IPv6 Router Advertisements with the
 * RDNSS (Recursive DNS Server) option.
 *
 * If we see an RDNSS option, we get the IPv6 address to the recursive
 * DNS and store it in a file in the resolv.conf format, resolver(5).
 *
 * Originally written by Michael Cardell Widerkrantz (MC) for
 * Stickybit AB and then maintained by MC.
 *
 * Contact:
 * 
 *   mc at the domain hack.org
 *
 * Copyright (c) 2008, Stickybit AB.
 * All rights reserved.
 *
 * Copyright (c) 2009, 2010, 2011 Michael Cardell Widerkrantz.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *    
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <pwd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "list.h"

/* #define DEBUG 1 */
/* #define TEST 1 */

#if DEBUG
#define PDEBUG(Args...) \
  do { fprintf(stderr, "radns: "); fprintf(stderr, ##Args); } while(0)
#else
#define PDEBUG(Args...)
#endif

#define RESOLVEFILE "./resolv.conf"

#define PIDFILE "/var/run/radns.pid"

#define USER "radns"

/* The Resolving DNS Server option, RFC 6106. */
#define ND_OPT_RDNSS  25

/* The DNS Search List option, RFC 6106. */
#define ND_OPT_DNSSL 31

/* Space for "nameserver %s \n" where %s is the IPv6 address */
#define NSADDRSIZE (13 + INET6_ADDRSTRLEN)
    
/*
 * XXX PACKETSIZE really taken out of the blue. Expected size of
 * incoming packets is:
 *
 *   ICMP6 header  8 bytes
 *   RA            minimum 24 bytes
 *   RDNSS option  minimum 24 bytes
 *
 * That is, minimum 56 bytes, with unknown max for patological cases.
 */
#define PACKETSIZE 1024

/*
 * Minimum length in bytes of the RDNSS option if we're going to care
 * about it. Exactly 3 * 8 = 24 octets if there is one IPv6 address.
 */
#define RDNSSMINLEN 24

/*
 * Lifetime that never expires.
 */ 
#define NEVEREXP 0xffffffff

/*
 * Maximum number of octets in a domain name as per RFC 1035
 */
#define MAXNAME 255

char *progname; /* argv[0] */
char *filename = RESOLVEFILE;
char *pidfilename = PIDFILE;
char *scriptname = NULL;
bool progdone;                /* true when we exit the program. */
int verbose = 0;                /* how much debug output? */
int localerrno;                 /* our own copy of errno. */
bool childcare = false;       /* true when we need to reap zombies. */

/*
 * Default for maximum number of stored resolver addresses. Can be
 * overridden by a runtime option.
 *
 * XXX A default called MAXNS might be in resolv.h, depending on
 * system. We might want to use that as default if it exists.
 */
int maxres = 3;

/*
 * Default for maximum number of stored domain suffixes.
 */ 
int maxsuf = 6;

struct resolver
{
    struct in6_addr addr;       /* Address to DNS server. */
    char ifname[IFNAMSIZ];      /* Interface name we received this data on. */
    time_t arrived;             /* Arrival time of packet. */
    time_t expire;              /* Expire time of this data. */
    bool neverexp;
    struct item *item;          /* Pointer to our place in the list. */
};

struct suffix
{
    char name[255];
    int len;               /* Length of domain name suffix. */
    char ifname[IFNAMSIZ];      /* Interface name we received this data on. */
    time_t expire;              /* Expire time of this data. */
    bool neverexp;
    struct item *item;          /* Pointer to our place in the list. */
};

/* Recursive DNS Server (RDNSS) option in Router Advertisments. */
struct nd_opt_rdnss
{
    uint8_t nd_opt_type; /* Should be 25 (0x19) for RDNSS */
    uint8_t nd_opt_len; /* Length: 3 (* 8 octets) if one IPv6
                           address. No of addresses = (Length -
                           1) / 2.  If less than 3, disregard.*/
    uint16_t nd_opt_rdns_res; /* Reserved. */
    uint32_t nd_opt_rdns_life; /* The maximum time in seconds to
                                  use this from the time it was
                                  sent. */
} __attribute__((__packed__));

/* DNS Search List option in Router Advertisments. */
struct nd_opt_dnssl
{ 
    uint8_t nd_opt_type;
    uint8_t nd_opt_len;
    uint16_t nd_opt_dnssl_res;
    uint32_t nd_opt_dnssl_life;
} __attribute__((__packed__));

static struct resolver *expirenext(struct item *reslist);
static struct resolver *findresolv(struct in6_addr addr, struct item *reslist);
static void deladdr(struct item **reslist, int *storedres,
                    struct in6_addr addr);
static void printrewrite(bool rewrite);
static void listsuf(struct item *suflist);
static void listres(struct item *reslist);
static void printrewrite(bool rewrite);
static bool rdnss(const struct nd_opt_rdnss *rdnssp, int optlen, 
           int lenleft, struct item **reslist, int *storedres,
           char ifname[IFNAMSIZ]);
static bool dnssl(const struct nd_opt_dnssl *dnsslp, int optlen, 
           int lenleft, struct item **suflist, int *storedsuf,
           char ifname[IFNAMSIZ]);
static int dnsname(char *domain, uint8_t *name, int buflen);
static void hexdump(uint8_t *buf, uint16_t len);
static void printhelp(void);
void sigcatch(int sig);
static int exithook(char *filename, char *ifname);
static int writeresolv(struct item *suflist, int storedsuf,
                       struct item *reslist);
static void logmsg(int pri, const char *message, ...);
static bool expireresolv(struct item **reslist, int *storedres);
static bool addresolver(struct item **reslist, int *storedres, uint32_t ttl,
                        struct in6_addr addr, char *ifname);
static void listres(struct item *reslist);
static bool addsuffix(struct item **suflist, int *storedsuf, uint32_t ttl,
                      char *name, int namelen, char *ifname);
static struct suffix *sufexpirenext(struct item *suflist);
static bool expiresuffix(struct item **suflist, int *storedsuf);
static struct suffix *findsuffix(char *name, int namelen, struct item *suflist);
static bool handle_icmp6(int sock, struct item **suflist, int *storedsuf,
                         struct item **reslist, int *storedres,
                         char ifname[IFNAMSIZ]);
static int mkpidfile(uid_t owner, gid_t group);

/*
 * Find resolver in list reslist that will expire next. Returns a
 * pointer to the resolver or NULL if there are no resolvers.
 */
static struct resolver *expirenext(struct item *reslist)
{
    time_t least = 0;
    struct resolver *res;
    struct resolver *leastres = NULL;
    struct item *item;
    
    for (item = reslist; item != NULL; item = item->next)
    {
        res = item->data;
        if (0 != res->expire)
        {
            if (0 == least || res->expire < least)
            {
                least = res->expire;
                leastres = res;
            }
        }
    }
    
    return leastres;
}

/*
 * Find resolver with address addr in list reslist. Returns a pointer
 * to the matching resolver or NULL if not found.
 */ 
static struct resolver *findresolv(struct in6_addr addr, struct item *reslist)
{
    struct item *item;
    struct resolver *res;
    
    for (item = reslist; item != NULL; item = item->next)
    {
        res = item->data;
        if (0 == memcmp(&addr, &res->addr, sizeof (addr)))
        {
            return res;
        }
    }

    return NULL;
}

/*
 * Delete the resolver res in list reslist.
 */

/*
 * Delete the resolver with address addr in list reslist.
 */ 
static void deladdr(struct item **reslist, int *storedres, struct in6_addr addr)
{
    struct resolver *res;
    
    res = findresolv(addr, *reslist);
    if (NULL == res)
    {
    }
    else
    {
        freeitem(reslist, storedres, res->item);
    }
}

/*
 * Print a list of all domain suffixes in suflist to stdout.
 */
static void listsuf(struct item *suflist)
{
    struct item *item;
    struct suffix *suf;
    int i;

    for (item = suflist, i = 1; item != NULL; item = item->next, i ++)
    {
        suf = item->data;

        printf("%i: received on if %s, expires at %d\n", i, 
               suf->ifname, (int)suf->expire);

        write(1, suf->name, suf->len);
        putchar('\n');
    }
}


/*
 * Print a list of all resolvers in reslist to stdout.
 */
static void listres(struct item *reslist)
{
    struct item *item;
    struct resolver *res;
    int i;
    char addrstr[INET6_ADDRSTRLEN];
    
    for (item = reslist, i = 1; item != NULL; item = item->next, i ++)
    {
        res = item->data;
        if (0 == res->expire)
        {
            printf("%i:  empty.\n", i);
        }
        else
        {
            if (NULL == inet_ntop(AF_INET6, &res->addr,
                                  addrstr, INET6_ADDRSTRLEN))
            {
                logmsg(LOG_ERR, "Couldn't convert IPv6 address to "
                       "string\n");
            }
            else
            {
                printf("%i:  %s, if %s, expire at %d\n", i, addrstr,
                       res->ifname, (int)res->expire);
            }
        }
    }
}

/*
 * Print on stdout if we need to rewrite or not.
 */ 
static void printrewrite(bool rewrite)
{
    if (rewrite)
    {
        printf("Rewrite.\n");
    }
    else
    {
        printf("No rewrite.\n");
    }
}


static bool rdnss(const struct nd_opt_rdnss *rdnssp, int optlen, 
                  int lenleft, struct item **reslist, int *storedres,
                  char ifname[IFNAMSIZ])
{
    int nr_of_addrs;
    int i;
    struct in6_addr *addrp;      /* An IPv6 address. */
    uint8_t *datap;            /* An octet pointer we use for running
                                 * through data in rdnssp. */
    bool rewrite = false;
    
    datap = (uint8_t *)rdnssp;
    
    /* We got an RDNSS option, that is,
     *
     * type, length, reserved,
     * lifetime
     * addresses
     */

    if (verbose > 2)
    {
        printf("  reserved: %d\n", rdnssp->nd_opt_rdns_res);
        printf("  lifetime: %d\n", ntohl(rdnssp->nd_opt_rdns_life));
    }
            
    /* Extract DNS address(es) from option. */

    /*
     * Length should be 3 (* 8 octets) if there is one IPv6
     * address. If less than 3 * 8 octets, disregard this
     * option.
     */
    if (optlen < RDNSSMINLEN)
    {
        /* No IPv6 address here. Throw away. */
        logmsg(LOG_INFO, "No IPv6 address in RDNSS option.\n");
        return rewrite;
    }

    /* Move to first IPv6 address. */
    datap += sizeof (struct nd_opt_rdnss);
    lenleft -= sizeof (struct nd_opt_rdnss);
            
    if (lenleft <= 0)
    {
        /* Out of data! */
        logmsg(LOG_INFO, "RDNSS option: Out of data.\n");
        return rewrite;
    }

    /* How many addresses to DNS servers are there? */
    nr_of_addrs = (rdnssp->nd_opt_len - 1) / 2;

    if (verbose > 0)
    {
        printf("%d address(es) to resolving DNS servers found.\n",
               nr_of_addrs);
    }
                
    /* Find the addresses and store them. */
    for (i = 0; i < nr_of_addrs
             && (unsigned)lenleft > sizeof (struct in6_addr); i ++)
    {
        addrp = (struct in6_addr *)datap;
            
        rewrite = addresolver(reslist, storedres,
                              ntohl(rdnssp->nd_opt_rdns_life),
                              *addrp, ifname);
                
        /* Move to next address, if any. */
        datap += sizeof (struct in6_addr);
        lenleft -= sizeof (struct in6_addr);
    } /* for */

    /* Tell caller if we need to rewrite the file. */
    return rewrite;
}


/*
 * Get a series of labels with RFC 1035 encoding in name and add them
 * to a domain string, domain.
 *
 * Returns length of final domain string which also happens to be the
 * number of bytes consumed by parsing in name.
 *
 * From RFC 1035:
 * 
 *   Domain names in messages are expressed in terms of a sequence of
 *   labels. Each label is represented as a one octet length field
 *   followed by that number of octets. Since every domain name ends
 *   with the null label of the root, a domain name is terminated by a
 *   length byte of zero. The high order two bits of every length
 *   octet must be zero, and the remaining six bits of the length
 *   field limit the label to 63 octets or less.
 *
 *   To simplify implementations, the total length of a domain name
 *   (i.e., label octets and label length octets) is restricted to 255
 *   octets or less.
 */
static int dnsname(char *domain, uint8_t *name, int buflen)
{
    uint8_t len;                /* Length of label. */
    uint8_t domleft = MAXNAME; /* Number of octets left free in domain. */
    int strlen;                 /* Length of domain string. */
    uint8_t *bytep;             /* Octet pointer used to walk the name. */

    strlen = 0;

    /*
     * Walk through each label and copy each label to the domain
     * string adding "." between them. When we run out of buffer
     * (pathological) or find a zero length (fine) we're done.
     */
    for (bytep = name; buflen > 0 && (uint8_t) *bytep != 0; )
    {
        len = *bytep;
        bytep ++;
        domleft --;
        
        if (domleft > len && len <= (uint8_t)buflen)
        {
            if (len != 0)
            {
                memcpy(&domain[strlen], bytep, len);
                bytep += len;
                domleft -= len;
                buflen -= len;
            
                strlen += len;
            }

            domain[strlen] = '.';
            strlen ++;
        }
    }
    
    return strlen;
}

static bool dnssl(const struct nd_opt_dnssl *dnsslp, int optlen, 
                  int lenleft, struct item **suflist, int *storedsuf,
                  char ifname[IFNAMSIZ])
{
    uint8_t *datap;            /* An octet pointer we use for running
                                 * through data in rdnssp. */
    bool rewrite = false;
    char domain[MAXNAME];
    int domlen;
    int optlenleft = optlen;
    
    if (verbose > 0)
    {
        printf("We received a DNSSL!\n");
    }

    datap = (uint8_t *)dnsslp;

    if (verbose > 2)
    {
        printf("  reserved: %d\n", dnsslp->nd_opt_dnssl_res);
        printf("  lifetime: %d\n", ntohl(dnsslp->nd_opt_dnssl_life));
    }

    /*
     * Length is at minimum 2 (* 8 octets) if there is exactly one
     * domain. If less, we disregard this option.
     */
    if (optlen < 2)
    {
        logmsg(LOG_INFO, "No Domain Suffix in DNSSL option.\n");
        return rewrite;        
    }

    /*
    Domain Names of DNS Search List
                  One or more domain names of DNS Search List that MUST
                  be encoded using the technique described in Section
                  3.1 of [RFC1035].  By this technique, each domain
                  name is represented as a sequence of labels ending in
                  a zero octet, defined as domain name representation.
                  For more than one domain name, the corresponding
                  domain name representations are concatenated as they
                  are.  Note that for the simple decoding, the domain
                  names MUST NOT be encoded in a compressed form, as
                  described in Section 4.1.4 of [RFC1035].  Because the
                  size of this field MUST be a multiple of 8 octets,
                  for the minimum multiple including the domain name
                  representations, the remaining octets other than the
                  encoding parts of the domain name representations
                  MUST be padded with zeros.
    */

    /* Move to first domain suffix. */
    datap += sizeof (struct nd_opt_dnssl);
    lenleft -= sizeof (struct nd_opt_dnssl);
    optlenleft -= sizeof (struct nd_opt_dnssl);

    if (lenleft <= 0)
    {
        /* Out of data! */
        logmsg(LOG_INFO, "DNSSL option: Out of data.\n");
        return rewrite;
    }

    while (optlenleft > 0 && lenleft > 0)
    {
        domlen = dnsname(domain, datap, optlenleft);
        if (0 == domlen)
        {
            break;
        }
        
        datap += domlen + 1;
        lenleft -= domlen + 1;
        optlenleft -= domlen + 1;
        
        printf("Got domain suffix:\n");
        hexdump((uint8_t *)domain, domlen);

        rewrite = addsuffix(suflist, storedsuf,
                            ntohl(dnsslp->nd_opt_dnssl_life), domain, domlen,
                            ifname);
    }
    
    return rewrite;
}

/*
 * Callback function when we get an ICMP6 message on socket sock.
 *
 * Returns true if we need to rewrite the resolv file and false
 * otherwise.
 */ 
static bool handle_icmp6(int sock, struct item **suflist, int *storedsuf,
                         struct item **reslist, int *storedres,
                         char ifname[IFNAMSIZ])
{
    uint8_t buf[PACKETSIZE];   /* The entire ICMP6 message. */
    int buflen;                 /* The lenght of the ICMP6 buffer. */
    uint8_t ancbuf[CMSG_SPACE(sizeof (struct in6_pktinfo)) ]; /* Ancillary
                                                               * data. */
    const struct nd_router_advert *ra; /* A Router Advertisement */
    struct nd_opt_hdr *ndhdr;    
    uint8_t *datap;            /* An octet pointer we use for running
                                 * through data in buf. */
    int lenleft;                /* Length left in buf, in bytes,
                                 * counting from datap. */
    struct sockaddr_in6 src;    /* Source address of RA packet. */
    struct iovec iov[1] =
        {
            { .iov_base = buf, .iov_len = sizeof (buf) }
        };                      /* Incoming buffer. */
    struct msghdr msg =
        {
            .msg_name = &src,
            .msg_namelen = sizeof (src),
            .msg_iov = iov,
            .msg_iovlen = sizeof (iov) / sizeof (iov[0]),
            .msg_control = ancbuf,
            .msg_controllen = sizeof (ancbuf)
        };                      /* Incoming message. */
    struct in6_pktinfo *pktinfo = NULL; /* Metadata about the packet. */
    struct cmsghdr *cmsgp;       /* Pointer to ancillary data. */
    struct timespec now;         /*  Time we received this packet. */
    bool rewrite = false;
    
    if (-1 == (buflen = recvmsg(sock, &msg, 0)))
    {
        logmsg(LOG_ERR, "read error on raw socket\n");
        return rewrite;
    }

    if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
    {
        logmsg(LOG_ERR, "truncated message\n");
        return rewrite;
    }

    /* Record when we received this packet. */
    if (-1 == clock_gettime(CLOCK_MONOTONIC, &now))
    {
        logmsg(LOG_ERR, "Couldn't get current time. Can't set arrival time.\n");
        now.tv_sec = 0;
    }

    /* Find our packet information (asked for by the IP6_RECVPKTINFO). */
    for (cmsgp = CMSG_FIRSTHDR(&msg); cmsgp != NULL;
         cmsgp = CMSG_NXTHDR(&msg, cmsgp))
    {
        if (cmsgp->cmsg_len == 0)
        {
            logmsg(LOG_ERR, "ancillary data with zero length.\n");
            return rewrite;
        }

        if ((cmsgp->cmsg_level == IPPROTO_IPV6) && (cmsgp->cmsg_type
                                                    == IPV6_PKTINFO))
        {
            pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsgp);
        }
    }

    if (NULL != pktinfo)
    {
        /* Convert it to an interface name. */
        if (NULL == if_indextoname(pktinfo->ipi6_ifindex, ifname))
        {
            logmsg(LOG_ERR, "couldn't find interface name: index %d\n",
                   pktinfo->ipi6_ifindex);
            strncpy(ifname, "<none>", IFNAMSIZ);
        }
    }
    else
    {
        strcpy(ifname, "");
    }

    if (verbose > 0)
    {
        char srcaddrstr[INET6_ADDRSTRLEN];          

        if (NULL == inet_ntop(AF_INET6, &src.sin6_addr, srcaddrstr,
                              INET6_ADDRSTRLEN))
        {
            logmsg(LOG_ERR, "Couldn't convert IPv6 address to string\n");
            return rewrite;
        }

        printf("Received an IPv6 Router Advertisement from %s on interface "
               "%s\n", srcaddrstr, ifname);

        if (NULL == inet_ntop(AF_INET6, &pktinfo->ipi6_addr, srcaddrstr,
                              INET6_ADDRSTRLEN))
        {
            logmsg(LOG_ERR, "Couldn't convert IPv6 address to string\n");
            return rewrite;
        }

        printf("Sent to: %s\n", srcaddrstr);
    }
    
    if (verbose > 2)
    {
        hexdump(buf, buflen);
    }

    /*
     * Keep buf and buflen pristine for possible later use. Walk the
     * buffer with datap.
     */
    datap = buf;
    lenleft = buflen;
    
    /* Get the router advertisement. */
    ra = (struct nd_router_advert *)datap;

    /* Check that it really is an RA, code 134 */
    if (ra->nd_ra_type != ND_ROUTER_ADVERT && ra->nd_ra_code != 0)
    {
        logmsg(LOG_INFO, "Not a Router Advertisement. Type: %d, code: %d. "
                "Why did we get it?\n",
                ra->nd_ra_type, ra->nd_ra_code);
        return rewrite;
    }

/*

  RFC 4861, Neighbor Discovery for IP version 6 (IPv6), which defines
  Router Advertisements says they look like this:
  
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      |     Code      |          Checksum             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Reachable Time                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                          Retrans Timer                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Options ...
  +-+-+-+-+-+-+-+-+-+-+-+-
*/

    if (verbose > 1)
    {
        printf("ICMP6 header\n");
        printf("  nd_ra_type: %d\n", ra->nd_ra_type);
        printf("  nd_ra_code: %d\n", ra->nd_ra_code);
        printf("  nd_ra_cksum: %d\n", ra->nd_ra_cksum);

        printf("RA:\n");
        printf("...\n");
        printf("  nd_ra_reachable: %ld\n", (long)ra->nd_ra_reachable);
        printf("  nd_ra_retransmit: %ld\n", (long)ra->nd_ra_retransmit);
    }
    
    /* Move pass the RA header to any options we might find. */
    datap += sizeof (struct nd_router_advert);
    lenleft -= sizeof (struct nd_router_advert);

    if (0 >= lenleft)
    {
        /* Out of data. */
        logmsg(LOG_INFO, "Missing data after RA header.\n");
        return rewrite;
    }

    /*
     * Check for the options we want. We're looking for option RDNSS,
     * 25.
     */
    if (verbose > 0)
    {
        printf("RA options:\n");
    }
    while (lenleft > 0)
    {
        int optlen;
        
        /*
         * This is what an option looks like:
         * 
         * 0                   1                   2                   3
         * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |     Type      |    Length     |              ...              |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * ~                              ...                              ~
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *
         *
         * Types:
         *
         * Source Link-Layer Address                    1
         * Target Link-Layer Address                    2
         * Prefix Information                           3
         * Redirected Header                            4
         * MTU                                          5
         *
         * RDNSS                                       25
         *
         * Length above is measured as a number of 64 bit components
         * including the type and length bytes.
         */

        ndhdr = (struct nd_opt_hdr *)datap;

        if (verbose > 0)
        {
            printf("  option type %d (0x%x)\n", ndhdr->nd_opt_type,
                 ndhdr->nd_opt_type);
        }

        /*
         * The nd_opt_len is the number of 64 bit units the option
         * contains including header.
         */
        optlen = ndhdr->nd_opt_len * 8;

        if (verbose > 2)
        {
            printf("  option length in header: %d (0x%x)\n", ndhdr->nd_opt_len,
                   ndhdr->nd_opt_len);

            printf("  actual length in bytes: %d\n", optlen);

            hexdump(datap, optlen);
        }

        switch (ndhdr->nd_opt_type)
        {
            bool rb;
            
        case ND_OPT_RDNSS:
            rb = rdnss((const struct nd_opt_rdnss *)datap,
                       optlen, lenleft, reslist, storedres,
                       ifname);

            rewrite = rewrite || rb;
            
            break;

        case ND_OPT_DNSSL:
            rb = dnssl((const struct nd_opt_dnssl *)datap,
                       optlen, lenleft, suflist, storedsuf, ifname);

            rewrite = rewrite || rb;

            break;

        default:
            /* Not a known option. */
            if (verbose > 1)
            {
                printf("Unknown RA option. Skipping...\n");
            }
            break;
        } /* switch */

        /* Advance beyond this option. */
        datap += optlen;
        lenleft -= optlen;        
    } /* while */  

    /* Tell caller if we need to rewrite resolv file. */
    return rewrite;
}

/*
 * Log a message either through syslog if we are daemonized or through
 * stderr if we're running in the foreground.
 *
 * pri is the syslog priority, such as LOG_INFO, message is the string
 * including format characters and the rest is optional variables
 * referenced by the format characters.
 *
 */ 
static void logmsg(int pri, const char *message, ...)
{
    va_list ap;

    va_start(ap, message);

    if (verbose > 0)
    {
        vfprintf(stderr, message, ap);
    }
    else
    {
        vsyslog(pri, message, ap);
    }

    va_end(ap);
}

/*
 * Call an external script to handle, for instance, interfacing with
 * the resolvconf program.
 *
 * filename is our own 'resolv.conf' and ifname is the name of the
 * local interface where we received the RA.
 *
 * Returns 0 on success.
 */ 
static int exithook(char *filename, char *ifname)
{
    pid_t pid;

    if (NULL == scriptname)
    {
        /* No script. */
        return 0;
    }
    
    pid = fork();
    if (-1 == pid)
    {
        logmsg(LOG_ERR, "couldn't fork.\n");
        return -1;
    }
    else if (0 == pid)
    {
        char *argv[2];
        char *env[3];

        /* We're in the child. */
        
        argv[0] = scriptname;
        argv[1] = NULL;

        if (NULL == (env[0] = calloc(sizeof (char), strlen(ifname))))
        {
            logmsg(LOG_ERR, "out of memory.\n");
            exit(1);
        }
        snprintf(env[0], 3 + strlen(ifname) + 1, "if=%s", ifname);
        
        if (NULL == (env[1] = calloc(sizeof (char), 13 + strlen(filename))))
        {
            logmsg(LOG_ERR, "out of memory.\n");
            exit(1);
        }
        snprintf(env[1], 13 + strlen(filename) + 1, "resolv_conf=%s", filename);

        env[2] = NULL;
        
        if (-1 == execve(scriptname, argv, env))
        {
            localerrno = errno;
            logmsg(LOG_ERR, "couldn't exec(): %s\nexiting...\n",
                   strerror(localerrno));
            exit(1);
        }
    } /* child */

    return 0;
}

/*
 * Write all the resolver addresses in list reslist in resolv file.
 * Returns 0 if successful, -1 otherwise.
 */ 
static int writeresolv(struct item *suflist, int storedsuf,
                       struct item *reslist)
{
    int filefd;
    char buf[NSADDRSIZE];
    char *tmpfn;
    struct item *item;
    struct resolver *res;
    struct suffix *suf;
    
    /*
     * Create a temporary file in the same directory as our real
     * resolver file.
     */
    if (-1 == asprintf(&tmpfn, "%s-work", filename))
    {
        logmsg(LOG_ERR, "Out of memory in writeresolv().\n");
        return -1;        
    }

    if (-1 == (filefd = open(tmpfn, O_CREAT | O_WRONLY | O_TRUNC, 0644)))
    {
        logmsg(LOG_ERR, "Couldn't open working file %s\n", tmpfn);
        goto bad;
    }

    if (verbose > 2)
    {
        printf("Writing addresses to temporary file %s.\n", tmpfn);
    }

    if (storedsuf > 0)
    {
        if (-1 == write(filefd, "search ", 7))
        {
            perror("write");
            goto bad;
        }

        /* Write search list to file. */
        for (item = suflist; item != NULL; item = item->next)
        {
            suf = item->data;

            /* FIXME: Do this in one write(). */        
            if (-1 == write(filefd, suf->name, suf->len))
            {
                perror("write");
                goto bad;
            }
            if (-1 == write(filefd, " ", 1))
            {
                perror("write");
                goto bad;
            }
        } /* for */

        if (-1 == write(filefd, "\n", 1))
        {
            perror("write");
            goto bad;
        }
    } /* if storedsuf */

    /* Write addresses to file. */
    for (item = reslist; item != NULL; item = item->next)
    {
        char addrstr[INET6_ADDRSTRLEN];          

        res = item->data;

        if (NULL == inet_ntop(AF_INET6, &res->addr,
                              addrstr, INET6_ADDRSTRLEN))
        {
            logmsg(LOG_ERR, "Couldn't convert IPv6 address to "
                   "string\n");
        }
        else
        {
            if (-1 == snprintf(buf, NSADDRSIZE, "nameserver %s\n",
                               addrstr))
            {
                perror("asprintf");
                goto bad;
            }
        
            if (-1 == write(filefd, buf, strlen(buf)))
            {
                perror("write");
                goto bad;
            }
        }
    } /* for */
    
    /* Set file mode. */
    if (-1 == fchmod(filefd, 0644))
    {
	localerrno = errno;
        logmsg(LOG_ERR, "Couldn't set file mode on %s: %s\n", tmpfn,
               strerror(localerrno));
        goto bad;
    }

    close(filefd);

    /* Rename the temporary file to the real resolv.conf file. */

    if (verbose > 0)
    {
        printf("Creating resolver file %s.\n", filename);
    }
    
    if (-1 == (rename(tmpfn, filename)))
    {
	localerrno = errno;        
        logmsg(LOG_ERR, "Couldn't rename %s to %s: %s\n", tmpfn, filename,
               strerror(localerrno));
        goto bad;
    }

    free(tmpfn);
    return 0;
    
bad:
    close(filefd);
    free(tmpfn);
    return -1;
}

/*
 * Dump the contents of pointer buf of length len as 16 bytes (32
 * hexadecimal digits) per row.
 */
static void hexdump(uint8_t *buf, uint16_t len)
{
    uint8_t *row; /* Pointer to rows of 16 bytes each. */
    uint8_t *byte; /* Pointer to each byte in the row. */
    uint8_t *max; /* Pointer to the maximum address in buf. */

    /*
     * Start the row where the buffer begins. Remember where it ends
     * (max). Stop when row is at max.
     *
     * For every byte in each row, print the value. If we reach the
     * 16th byte, start a new row.
     */
    row = buf;
    max = &buf[len];
    for (byte = 0; byte != max; row = byte)
    {
        /* Print byte offset. */
        printf("%07tx ", row - buf);

        for (byte = row; byte != max && byte != (row + 16); byte ++)
        {
            printf("%02x ", *byte);
        }

        (void)putchar('\n');
    } /* Outer for */
}

/* Prints a helpful message. */
static void printhelp(void)
{
    fprintf(stderr, "Usage: %s [-v [-v] [-v]] [-f filename] [-m max resolvers] "
            "[-u user] [-s script] [-p pidfile ]\n", progname);

    fprintf(stderr, "-f filename gives the filename the DNS resolving address "
            "is written to. Default is ./resolv.conf.\n");
    fprintf(stderr, "-m number-of-resolvers sets an upper limit of how many "
            "resolver addresses to store. 0 means no upper limit.\n");
    fprintf(stderr, "-u user sets username to drop privileges to. "
            "Default is 'radns'.\n");
    fprintf(stderr, "-s script executes 'script' after receiving a Router "
            "Advertisment.\n");
    fprintf(stderr, "-p pidfile writes the process ID to 'pidfile'. By default "
            "it writes the process ID to %s.\n", PIDFILE);

    fprintf(stderr, "Repeating -v means more verbosity.\n");
    fprintf(stderr, "Use -V to get version information.\n");
}

/* Signal handler for SIGCHLD. */
void sigcatch(int sig)
{
    if (SIGCHLD == sig)
    {
        /* A child process died. Tell main loop to deal with it. */
        childcare = true;
    }
    else
    {
        progdone = true;
    }
}

static struct suffix *findsuffix(char *name, int namelen, struct item *suflist)
{
    struct item *item;
    struct suffix *suf;
    
    for (item = suflist; item != NULL; item = item->next)
    {
        suf = item->data;

        if (namelen == suf->len && 0 == memcmp(name, suf->name, suf->len))
        {
            return suf;
        }
    }

    return NULL;
}

static struct suffix *sufexpirenext(struct item *suflist)
{
    time_t least = 0;
    struct suffix *suf;
    struct suffix *leastsuf = NULL;
    struct item *item;
    
    for (item = suflist; item != NULL; item = item->next)
    {
        suf = item->data;
        if (0 != suf->expire)
        {
            if (0 == least || suf->expire < least)
            {
                least = suf->expire;
                leastsuf = suf;
            }
        }
    }
    
    return leastsuf;
}

static bool expiresuffix(struct item **suflist, int *storedsuf)
{
    int expired = false;
    struct timespec now;    
    struct item *item;
    struct suffix *suf;
    
    if (-1 == clock_gettime(CLOCK_MONOTONIC, &now))
    {
        logmsg(LOG_ERR, "Couldn't get current time. Can't expire.\n");
        return expired;
    }

    for (item = *suflist; item != NULL; item = item->next)
    {
        suf = item->data;
        if (NEVEREXP == (unsigned) suf->expire)
        {
            break;
        }

        if (0 != suf->expire && suf->expire <= now.tv_sec)
        {
            expired = true;

            freeitem(suflist, storedsuf, suf->item);

            if (verbose > 1)
            {
                printf("Suffix expired.\n");
            }
        }
    } /* for */

    return expired;    
}

/*
 * Add or update a domain name suffix in list suflist. Returns true if
 * we need to rewrite the resolv file.
 */
static bool addsuffix(struct item **suflist, int *storedsuf, uint32_t ttl,
                      char *name, int namelen, char *ifname)
{
    struct timespec now;
    struct suffix *suf;
    struct item *item;
    
    if (-1 == clock_gettime(CLOCK_MONOTONIC, &now))
    {
        logmsg(LOG_ERR, "Couldn't get current time. Can't set expire time.\n");
        now.tv_sec = 0;
    }
    
    /* Do we know this address already? */
    suf = findsuffix(name, namelen, *suflist);

    if (verbose > 0)
    {
        printf("New suffix is ");

        if (NULL == suf)
        {
            printf("unknown.\n");
        }
        else
        {
            printf("already known.\n");
        }
    }
    
    if (NULL != suf)
    {
        /* Yes we know this suffix. */
        if (0 == ttl)
        {
            /*
             * TTL from RA is 0, so we're asked to delete this domain
             * suffix. Requires rewriting of file. Finished.
             */
            if (verbose > 0)
            {
                printf("We have been asked to remove it, so we do.\n");
            }

            freeitem(suflist, storedsuf, suf->item);
            return true;
        }
        else
        {
            /*
             * Time to live != 0: Increase expire time or set the
             * resolver to never expire. Doesn't require rewriting.
             * Finished.
             */
            if (verbose > 0)
            {
                printf("Updating ttl with %d seconds from now.\n", ttl);
            }
            if (NEVEREXP == ttl)
            {
                suf->neverexp = true;
            }
            else
            {
                suf->expire = now.tv_sec + ttl;
            }

            return false;
        }
    }
    else
    {
        /*
         * The new suffix is unknown to us.
         * 
         * Insert at head. If the list has a maximum number of items
         * and we're full, replace the suffix about to expire next.
         * 
         * Requires rewriting of resolv file.
         *
         */

        if (verbose > 1)
        {
            printf("%d suffixes of max %d already stored.\n", *storedsuf,
                   maxsuf);
        }

        /* 0 is the special case of unlimited number of elements. */
        if (0 != maxsuf && *storedsuf == maxsuf)
        {
            /*
             * We're full. Find the first to expire and replace that.
             */
            if (verbose > 1)
            {
                printf("We're full. Finding a suffix to replace.");
            }
            suf = sufexpirenext(*suflist);
        }
        else
        {
            if (verbose > 1)
            {
                printf("Adding a new suffix.\n");
            }

            item = additem(suflist);
            suf = malloc(sizeof (struct suffix));
            if (NULL == suf)
            {
                logmsg(LOG_ERR, "Couldn't allocate memory for new suffix.\n");
                delitem(suflist, item);
                return false;
            }

            item->data = suf;
            suf->item = item;

            (*storedsuf) ++;
        }
        
        PDEBUG("Copying data...\n");
            
        memcpy(suf->name, name, namelen);
        suf->len = namelen;
        strncpy(suf->ifname, ifname, IFNAMSIZ);

        if (NEVEREXP == ttl)
        {
            PDEBUG("Never expire.\n");
            suf->neverexp = true;
        }
        else
        {
            PDEBUG("New expire is now (%d) + ttl (%d) = %d\n", now.tv_sec, ttl,
                   now.tv_sec + ttl);
            suf->expire = now.tv_sec + ttl;
        }
        
        return true;
    }
}

/*
 * Add or update a resolver address in list reslist. Returns true if
 * we need to rewrite the resolv file.
 *
 * storedres - pointer to number of stored resolvers.
 * ttl - time to live as from RA.
 * addr - the IPv6 address to the resolver.
 * ifname - interface name string
 */ 
static bool addresolver(struct item **reslist, int *storedres, uint32_t ttl,
                        struct in6_addr addr, char *ifname)
{
    struct timespec now;
    struct resolver *res;
    struct item *item;
    
    if (-1 == clock_gettime(CLOCK_MONOTONIC, &now))
    {
        logmsg(LOG_ERR, "Couldn't get current time. Can't set expire time.\n");
        now.tv_sec = 0;
    }
    
    /* Do we know this address already? */
    res = findresolv(addr, *reslist);

    if (verbose > 0)
    {
        char addrstr[INET6_ADDRSTRLEN];

        if (NULL == inet_ntop(AF_INET6, &addr, addrstr, INET6_ADDRSTRLEN))
        {
            logmsg(LOG_ERR, "Couldn't convert IPv6 address to string.\n");
            return false;
        }

        printf("%s is ", addrstr);
        if (NULL == res)
        {
            printf("unknown.\n");
        }
        else
        {
            printf("already known.\n");
        }
    }
    
    if (NULL != res)
    {
        /* Yes we know this address. */
        if (0 == ttl)
        {
            /*
             * TTL from RA is 0, so we're asked to delete this
             * resolver. Requires rewriting of file. Finished.
             */
            if (verbose > 0)
            {
                printf("We have been asked to remove it, so we do.\n");
            }

            freeitem(reslist, storedres, res->item);

            return true;
        }
        else
        {
            /*
             * Time to live != 0: Increase expire time or set the
             * resolver to never expire. Doesn't require rewriting.
             * Finished.
             */
            if (verbose > 0)
            {
                printf("Updating ttl with %d seconds from now.\n", ttl);
            }
            if (NEVEREXP == ttl)
            {
                res->neverexp = true;
            }
            else
            {
                res->expire = now.tv_sec + ttl;
            }

            return false;
        }
    }
    else
    {
        /*
         * The new resolver is unknown to us.
         * 
         * Insert at head. If the list has a maximum number of items
         * and we're full, replace the resolver about to expire next.
         *
         * Requires rewriting of resolv file.
         *
         */

        if (verbose > 1)
        {
            printf("%d resolvers of max %d already stored.\n", *storedres,
                   maxres);
        }

        /* 0 is the special case of unlimited number of elements. */
        if (0 != maxres && *storedres == maxres)
        {
            /*
             * We're full. Find the first address to expire and
             * replace that.
             */
            if (verbose > 1)
            {
                printf("We're full. Finding a resolver to replace.");
            }
            res = expirenext(*reslist);
        }
        else
        {
            /* We have room. Add new item. */
            if (verbose > 1)
            {
                printf("Adding a new resolver.\n");
            }

            item = additem(reslist);
            res = malloc(sizeof (struct resolver));
            if (NULL == res)
            {
                logmsg(LOG_ERR, "Couldn't allocate memory for new resolver.\n");
                delitem(reslist, item);
                return false;
            }
            
            item->data = res;
            res->item = item;
            (*storedres) ++;
        }

        PDEBUG("Copying data...\n");
            
        memcpy(&res->addr, &addr, sizeof (struct in6_addr));
        strncpy(res->ifname, ifname, IFNAMSIZ);

        if (NEVEREXP == ttl)
        {
            PDEBUG("Never expire.\n");
            res->neverexp = true;
        }
        else
        {
            PDEBUG("New expire is now (%d) + ttl (%d) = %d\n", now.tv_sec, ttl,
                   now.tv_sec + ttl);
            res->expire = now.tv_sec + ttl;
        }
        
        return true;
    }
}

/*
 * Delete any expired DNS resolvers in list reslist with storedres
 * number of resolvers. Returns need to rewrite.
 */ 
static bool expireresolv(struct item **reslist, int *storedres)
{
    int expired = false;
    struct timespec now;    
    struct item *item;
    struct resolver *res;
    
    if (-1 == clock_gettime(CLOCK_MONOTONIC, &now))
    {
        logmsg(LOG_ERR, "Couldn't get current time. Can't expire.\n");
        return expired;
    }

    for (item = *reslist; item != NULL; item = item->next)    
    {
        res = item->data;        
        if (NEVEREXP == (unsigned) res->expire)
        {
            break;
        }

        if (0 != res->expire && res->expire <= now.tv_sec)
        {
            expired = true;

            freeitem(reslist, storedres, res->item);
            
            if (verbose > 1)
            {
                char srcaddrstr[INET6_ADDRSTRLEN];          

                if (NULL == inet_ntop(AF_INET6, &res->addr,
                                      srcaddrstr, INET6_ADDRSTRLEN))
                {
                    logmsg(LOG_ERR, "Couldn't convert IPv6 address to "
                           "string\n");
                }
                else
                {
                    printf("Resolver %s expired.\n", srcaddrstr);
                }
            }
        } /* if expire */
    } /* for */

    return expired;
}

/*
 * Write a file with the current process ID.
 *
 * Returns 0 on success.
 */ 
static int mkpidfile(uid_t owner, gid_t group)
{
    int filefd;
    char *buf = NULL;
    int rc = 0;
    
    if (-1 == (filefd = open(pidfilename, O_CREAT | O_WRONLY | O_TRUNC, 0644)))
    {
        logmsg(LOG_ERR, "couldn't open pidfile %s\n", pidfilename);
        rc = -1;        
	goto end;
    }
    
    if (-1 == asprintf(&buf, "%u\n", (unsigned) getpid()))
    {
	logmsg(LOG_ERR, "couldn't allocate memory for pid\n");
        rc = -1;        
	goto end;
    }

    if (-1 == write(filefd, buf, strlen(buf)))
    {
	localerrno = errno;
	logmsg(LOG_ERR, "couldn't write pid: %s\n", strerror(localerrno));
        rc = -1;
	goto end;
    }

    /*
     * Change owner of file to our new user so we are allowed to
     * remove it later, after dropping privileges.
     */
    if (0 != lchown(pidfilename, owner, group))
    {
        localerrno = errno;
	logmsg(LOG_ERR, "couldn't change owner of file %s\n", pidfilename,
               strerror(localerrno));
        rc = -1;
        goto end;
    }
    
end:
    close(filefd);

    if (NULL != buf)
    {
	free(buf);
    }

    return rc;
}

/************************************************************************/
/* Test main                                                            */
/************************************************************************/
#ifdef TEST
int main(void)
{
    struct item *reslist = NULL; /* Linked list of resolvers. */
    struct item *suflist = NULL; /* Linked list of domain suffixes. */
    int storedres = 0;
    int storedsuf = 0;
    struct in6_addr addr;
    bool rewrite;
    struct suffix *suf;

        char domain[MAXNAME];
    int domainlen;
    
    domainlen = dnsname(domain, (uint8_t *)"\007example\003com\000", 13);

    printf("Domain length %d\n", domainlen);
    hexdump((uint8_t *)domain, domainlen);

    domainlen = dnsname(domain, (uint8_t *)"\007example\003com\000foobar",
                        13 + 6);

    printf("Domain length %d\n", domainlen);
    hexdump((uint8_t *)domain, domainlen);

    printf("Suffixes (should be none)\n");
    listsuf(suflist);

    printf("Adding hack.org.\n");
    rewrite = addsuffix(&suflist, &storedsuf, 30, "hack.org.", 9, "em0");
    printrewrite(rewrite);
    listsuf(suflist);

    suf = sufexpirenext(suflist);
    
    printf("Deleting suffix.\n");
    freeitem(&suflist, &storedsuf, suf->item);
    listsuf(suflist);
    
    printf("Resolvers (should be none):\n");
    listres(reslist);

    /* Add a new resolver. */
    puts("\n1:");    
    if (-1 == inet_pton(AF_INET6, "::1", &addr))
    {
        logmsg(LOG_ERR, "Couldn't convert IPv6 address to string\n");
        exit(1);
    }
    rewrite = addresolver(&reslist, &storedres, 30, addr, "em0");
    printrewrite(rewrite);
    listres(reslist);
    sleep(1);
    
    puts("\nAdd the same again:");
    if (-1 == inet_pton(AF_INET6, "::1", &addr))
    {
        logmsg(LOG_ERR, "Couldn't convert IPv6 address to string\n");
        exit(1);
    }
    rewrite = addresolver(&reslist, &storedres, 30, addr, "em0");
    printrewrite(rewrite);
    listres(reslist);    
    sleep(1);
    
    /* Add a new resolver. */
    puts("\n3:");    
    if (-1 == inet_pton(AF_INET6, "fe80::216:d3ff:fe21:5a5a", &addr))
    {
        logmsg(LOG_ERR, "Couldn't convert IPv6 address to string\n");
        exit(1);
    }
    rewrite = addresolver(&reslist,&storedres, 120, addr, "em0");
    printrewrite(rewrite);    
    listres(reslist);
    sleep(1);

    /* Delete a resolver. */
    if (-1 == inet_pton(AF_INET6, "::1", &addr))
    {
        logmsg(LOG_ERR, "Couldn't convert IPv6 address to string\n");
        exit(1);
    }
    PDEBUG("Deleting ::1.\n");
    deladdr(&reslist, &storedres, addr);
    
    /* Add a new resolver. */
    puts("\n4:");        
    if (-1 == inet_pton(AF_INET6, "2001::216:d3ff:fe21:5a5a", &addr))
    {
        logmsg(LOG_ERR, "Couldn't convert IPv6 address to string\n");
        exit(1);
    }
    rewrite = addresolver(&reslist,&storedres, 120, addr, "em0");
    printrewrite(rewrite);        
    listres(reslist);
    sleep(1);
    
    /* Add a new resolver. */
    puts("\n5:");            
    if (-1 == inet_pton(AF_INET6, "2001:16d8:ffff:1:213:2ff:fe0e:9cfa", &addr))
    {
        logmsg(LOG_ERR, "Couldn't convert IPv6 address to string\n");
        exit(1);
    }
    rewrite = addresolver(&reslist,&storedres, 120, addr, "wlan1");
    printrewrite(rewrite);        
    listres(reslist);
    sleep(1);

    /* Add a new resolver. */
    puts("\n6:");            
    if (-1 == inet_pton(AF_INET6, "2001:16d8:ffff:1:213:2ff:cafe:babe", &addr))
    {
        logmsg(LOG_ERR, "Couldn't convert IPv6 address to string\n");
        exit(1);
    }
    rewrite = addresolver(&reslist,&storedres, 120, addr, "wlan1");
    printrewrite(rewrite);        
    listres(reslist);
    sleep(1);
    
    delallitems(&reslist, &storedres);
    
    exit(0);
}
#else
/************************************************************************/
/* Real main                                                            */
/************************************************************************/
int main(int argc, char **argv)
{
    char ch;                    /* Option character */
    int sock;               /* Raw socket file descriptor */
    struct icmp6_filter filter; /* Filter for raw socket. */
    int on;                     /* Just a flag for setsockopts... */
    fd_set in;                  
    int found;
    char *user = USER;          /* Username we will run as. */
    struct passwd *pw;          /* User data, for uid and gid. */
    struct sigaction sigact;    /* Signal handler. */
    struct stat sb;             /* For stat() */
    struct item *reslist = NULL; /* List of resolver addresses. */
    int storedres = 0;           /* Number of addresses in list. */
    struct item *suflist = NULL; /* List of domain suffixes. */        
    int storedsuf = 0;           /* Number of suffixes in list. */    
    char ifname[IFNAMSIZ];       /* Name of local interface. */
        
    progname = argv[0];

    /* Install signal handlers. */

    sigact.sa_flags = 0;
    sigact.sa_handler = sigcatch;
    sigemptyset(&sigact.sa_mask);
    
    sigaction(SIGCHLD, &sigact, NULL);
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGQUIT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    sigact.sa_handler = SIG_IGN;    
    sigaction(SIGHUP, &sigact, NULL);    

    while (1)
    {
        ch = getopt(argc, argv, "f:m:s:p:u:vV");
        if (-1 == ch)
        {
            /* No more options, break out of while loop. */
            break;
        }

        switch (ch)
        {
        case 'f':
            filename = optarg;
            break;
        case 'm':
            maxres = atoi(optarg);
            break;
        case 'p':
            pidfilename = optarg;
            break;
        case 's':
            scriptname = optarg;
            break;
        case 'u':
            user = optarg;
            break;
        case 'v':
            verbose ++;
            break;
        case 'V':
            fprintf(stderr, "radns version %s\n", VERSION);
            exit(0);
            break;
        default:
            printhelp();
            exit(1);
        }
    } /* while */
    
    if (-1 == (sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)))
    {
        logmsg(LOG_ERR, "Error from socket(). Perhaps you're not running as "
               "root? Terminating.\n");
        exit(1);
    }

    /*
     * Daemonize if we're not told to do otherwise. Don't change
     * directory to /, though.
     */
    if (0 == verbose)
    {
        openlog(argv[0], LOG_PID | LOG_NDELAY, LOG_DAEMON);

        if (0 != daemon(1, 0))
        {
            logmsg(LOG_ERR, "Error from daemon(). Terminating.\n");
            exit(1);
        }
    }
    
    /* Get user information. */
    if (NULL == (pw = getpwnam(user)))
    {
        logmsg(LOG_ERR, "couldn't find user '%s'.\n", user);
        exit(1);
    }

    /* Write our pid to a file. We still need to be root to be able to
     * write to /var/run...
     */
    if (-1 == mkpidfile(pw->pw_uid, pw->pw_gid))
    {
        logmsg(LOG_ERR, "Couldn't create pid file.\n");
    }

    /* Dropping privileges. */
    /* FIXME: setgroups() as well? */
    if (0 != setgid(pw->pw_gid) || 0 != setuid(pw->pw_uid))
    {
        logmsg(LOG_ERR, "couldn't drop privileges\n");
        exit(1);
    }

    /****************** Now running as radns user. ******************/
    
    /* Check if there's a script. */
    if (NULL != scriptname && 0 != stat(scriptname, &sb))
    {
        localerrno = errno;
        logmsg(LOG_ERR, "Script file %s: %s. Terminating.\n", scriptname,
               strerror(localerrno));
        exit(1);
    }

    /* Initialize resolv file and make sure we can write to it early. */
    if (0 != writeresolv(suflist, storedsuf, reslist))
    {
        logmsg(LOG_ERR, "Couldn't create resolv file %s. Exiting...\n",
               filename);
        exit(1);
    }

    /* Set a filter so we only get ICMPv6 packets. */
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);

    if (-1 == setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
                         sizeof(filter)))
    {
        logmsg(LOG_ERR, "Error from setsockopt(). Terminating.\n");
        exit(1);
    }

    /*
     * Ask for ancillary data with each ICMPv6 packet so we can get
     * the incoming interface name.
     */
    on = 1;
    if (-1 == setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
                         sizeof(on)))
    {
        logmsg(LOG_ERR, "Error from setsockopt(). Terminating.\n");
        exit(1);
    }

    /* Main loop. */
    for (progdone = false; !progdone; )
    {
        int status;
        bool newresolv = false;
        struct timeval tv;
        struct timespec now;
        struct resolver *res;
        
        /* Figure out when to wake up. */
        if (-1 == clock_gettime(CLOCK_MONOTONIC, &now))
        {
            logmsg(LOG_ERR, "Couldn't get current time.\n");
            now.tv_sec = 0;
            now.tv_nsec = 0;
        }

        res = expirenext(reslist);
        if (NULL == res)
        {
            tv.tv_sec = 0;
        }
        else
        {
            tv.tv_sec = res->expire - now.tv_sec;
            tv.tv_usec = 0;
        }
        
        FD_ZERO(&in);
        FD_SET(sock, &in);

        if (0 == tv.tv_sec)
        {
            /* No timeout. Block while waiting for incoming packet. */
            found = select(sock + 1, &in, NULL, NULL, NULL);
        }
        else
        {
            /* Wait for incoming packet or the next expire. */
            found = select(sock + 1, &in, NULL, NULL, &tv);
        }

        if (-1 == found)
        {
            localerrno = errno;
            if (EINTR != localerrno)
            {
                logmsg(LOG_ERR, "select failed: %s\n", strerror(localerrno));
                exit(1);
            }
        }
        else
        {
            if (-1 != sock && FD_ISSET(sock, &in))
            {
                if (handle_icmp6(sock, &suflist, &storedsuf, &reslist,
                                 &storedres, ifname))
                {
                    /* We got a new message and we need to rewrite. */
                    newresolv = true;
                }
            } /* sock */
        } /* if found */

        /* FIXME: Check for expired suffixes. */
        
        /* Check for expired DNS servers. */
        if (expireresolv(&reslist, &storedres))
        {
            /* Some resolvers expired. Maybe do something. */
            newresolv = true;
        }

        /* Check for expired domain suffixes. */
        if (expiresuffix(&suflist, &storedsuf))
        {
            /* Some suffixes expired. Maybe do something. */
            newresolv = true;            
        }
        
        if (newresolv)
        {
            /* Write address(es) to file. */        
            writeresolv(suflist, storedsuf, reslist);

            /* Call external script, if any. */
            (void)exithook(filename, ifname);

            newresolv = false;
        }
        
        /* Reap any zombie exit hook script(s) we might have. */
        if (childcare)
        {
            while (-1 != waitpid(-1, &status, WNOHANG))
                ;
            childcare = false;
        }

    } /* for */

    logmsg(LOG_INFO, "Terminating.\n");

    /* Free all resolvers and suffixes. Write an empty resolv file. */
    delallitems(&reslist, &storedres);
    delallitems(&suflist, &storedsuf);
    writeresolv(suflist, storedsuf, reslist);
    
    exit(0);
}
#endif
