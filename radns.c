/*
 * radns - Router Advertisement DNS
 *
 * Small program to listen for IPv6 Router Advertisements with the
 * RDNSS (Recursive DNS Server) option.
 *
 * If we see an RDNSS option, we get the IPv6 address to the recursive
 * DNS and store it in a file. The default filename is
 * "./resolv.conf".
 *
 * Example usage:
 *
 *   radns -f /etc/ra-resolv.conf
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
 * Copyright (c) 2009, 2010 Michael Cardell Widerkrantz.
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

#ifdef __GLIBC__
/* Needed for in6_pktinfo on modern GNU libc releases. */
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#ifdef DMALLOC
#include <dmalloc.h>
#endif

/* Might be in resolv.h, depending on system. */
#define MAXNS 3

#define RESOLVEFILE "./resolv.conf"

#define PIDFILE "/var/run/radns.pid"

#define USER "radns"

/* The Resolving DNS Server option, RFC 5006. */
#define ND_OPT_RDNSS  25

/* Space for "nameserver %s \n" where %s is the IPv6 address */
#define NSADDRSIZE (12 + INET6_ADDRSTRLEN)
    
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

char *progname; /* argv[0] */
char *filename = RESOLVEFILE;
char *pidfilename = PIDFILE;
char *scriptname = NULL;
int progdone = 0;               /* true when we exit the program. */
int verbose = 0;                /* how much debug output? */
int localerrno;                 /* our own copy of errno. */
int childcare = 0;              /* true when we need to reap zombies. */

struct resolvdns
{
    struct in6_addr addr;       /* Address to DNS server. */
    char ifname[IFNAMSIZ];      /* Interface name we received this data on. */
    time_t arrived;             /* Arrival time of packet. */
    time_t expire;              /* Expire time of this data. */
};

/*
 * Array of printable IPv6 addresses.
 */ 
struct straddrs
{
    char **addrbuf;
    int num; /* The number of addresses held in addrbuf. */
};

static void hexdump(uint8_t *buf, uint16_t len);
static void printhelp(void);
void sigcatch(int sig);
static int exithook(char *filename, char *ifname);
static int compare(const void *first, const void *second);
static void writeresolv(struct resolvdns resolv[]);
static void logmsg(int pri, const char *message, ...);
static time_t resolvttl(struct resolvdns resolv[]);
static int expireresolv(struct resolvdns resolv[]);
static void resetresolv(struct resolvdns resolv[]);
static void addresolver(struct resolvdns resolver, struct resolvdns resolv[]);
int handle_icmp6(int sock, struct resolvdns resolvers[], char ifname[IFNAMSIZ]);
int mkpidfile(uid_t owner, gid_t group);
    
/*
 * Callback function when we get an ICMP6 message on socket sock.
 */ 
int handle_icmp6(int sock, struct resolvdns resolvers[], char ifname[IFNAMSIZ])
{
    uint8_t buf[PACKETSIZE];   /* The entire ICMP6 message. */
    int buflen;                 /* The lenght of the ICMP6 buffer. */
    uint8_t ancbuf[CMSG_SPACE(sizeof (struct in6_pktinfo)) ]; /* Ancillary data. */
    const struct nd_router_advert *ra; /* A Router Advertisement */
    const struct nd_opt_rdnss
    {
	uint8_t nd_opt_type; /* Should be 25 (0x19) for RDNSS */
	uint8_t nd_opt_len; /* Length: 3 (* 8 octets) if one IPv6
                                address. No of addresses = (Length -
                                1) / 2.  If less than 3, disregard.*/
        uint16_t nd_opt_rdns_res; /* Reserved. */
        uint32_t nd_opt_rdns_life; /* The maximum time in seconds to
                                       use this from the time it was
                                       sent. */
    } *rdnss;
    uint8_t *datap;            /* An octet pointer we use for running
                                 * through data in buf. */
    int lenleft;                /* Length left in buf, in bytes,
                                 * counting from datap. */
    struct in6_addr *addrp;      /* An IPv6 address. */

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
    struct in6_pktinfo *pktinfo; /* Metadata about the packet. */
    struct cmsghdr *cmsgp;       /* Pointer to ancillary data. */
    struct resolvdns resolver;
    struct timeval now;         /*  Time we received this packet. */
    
    if (-1 == (buflen = recvmsg(sock, &msg, 0)))
    {
        logmsg(LOG_ERR, "read error on raw socket\n");
        return -1;
    }

    if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
    {
        logmsg(LOG_ERR, "truncated message\n");
        return -1;
    }

    /* Record when we received this packet. */
    if (-1 == gettimeofday(&now, NULL))
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
            return -1;
        }

        if ((cmsgp->cmsg_level == IPPROTO_IPV6) && (cmsgp->cmsg_type
                                                    == IPV6_PKTINFO))
        {
            pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsgp);
        }
    }

    /* Convert it to an interface name. */
    if (NULL == if_indextoname(pktinfo->ipi6_ifindex, ifname))
    {
        logmsg(LOG_ERR, "couldn't find interface name: index %d\n", pktinfo->ipi6_ifindex);
        strncpy(ifname, "<none>", IFNAMSIZ);
    }

    if (verbose > 1)
    {
        char srcaddrstr[INET6_ADDRSTRLEN];          

        if (NULL == inet_ntop(AF_INET6, &src.sin6_addr, srcaddrstr,
                              INET6_ADDRSTRLEN))
        {
            logmsg(LOG_ERR, "Couldn't convert IPv6 address to string\n");
            return -1;
        }
        
        printf("Received an IPv6 Router Advertisement from %s on interface "
               "%s\n", srcaddrstr, ifname);

        if (NULL == inet_ntop(AF_INET6, &pktinfo->ipi6_addr, srcaddrstr,
                              INET6_ADDRSTRLEN))
        {
            logmsg(LOG_ERR, "Couldn't convert IPv6 address to string\n");
            return -1;
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
        return -1;
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
        return -1;
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

        rdnss = (struct nd_opt_rdnss *)datap;

        if (verbose > 0)
        {
            printf("  option type %d (0x%x)\n", rdnss->nd_opt_type,
                 rdnss->nd_opt_type);
        }

        /*
         * The nd_opt_len is the number of 64 bit units the option
         * contains including header.
         */
        optlen = rdnss->nd_opt_len * 8;

        if (verbose > 2)
        {
            printf("  option length in header: %d (0x%x)\n", rdnss->nd_opt_len,
                   rdnss->nd_opt_len);

            printf("  actual length in bytes: %d\n", optlen);

            hexdump(datap, optlen);
        }
        
        if (rdnss->nd_opt_type == ND_OPT_RDNSS)
        {
            int nr_of_addrs;
            int i;
            
            /* We got an RDNSS option, that is,
             *
             * type, length, reserved,
             * lifetime
             * addresses
             */

            if (verbose > 2)
            {
                printf("  reserved: %d\n", rdnss->nd_opt_rdns_res);
                printf("  lifetime: %d\n", ntohl(rdnss->nd_opt_rdns_life));
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
                return -1;
            }

            /* Move to first IPv6 address. */
            datap += sizeof (struct nd_opt_rdnss);
            lenleft -= sizeof (struct nd_opt_rdnss);
            
            if (lenleft <= 0)
            {
                /* Out of data! */
                logmsg(LOG_INFO, "RDNSS option: Out of data.\n");
                return -1;
            }

            /* How many addresses to DNS servers are there? */
            nr_of_addrs = (rdnss->nd_opt_len - 1) / 2;

            if (verbose > 0)
            {
                printf("%d address(es) to resolving DNS servers found.\n",
                       nr_of_addrs);
            }
                
            /* Find the addresses and store them. */
            for (i = 0; i < nr_of_addrs; i ++)
            {
                addrp = (struct in6_addr *)datap;

                memcpy(&resolver.addr, addrp, sizeof (struct in6_addr));
                strncpy(resolver.ifname, ifname, IFNAMSIZ);
                resolver.arrived = now.tv_sec;
                resolver.expire = ntohl(rdnss->nd_opt_rdns_life);
            
                addresolver(resolver, resolvers);
                
                /* Move to next address, if any. */
                datap += sizeof (struct in6_addr);
                lenleft -= sizeof (struct in6_addr);
            } /* for */
        }
        else
        {
            /* Not an RDNSS option. Skip it. */
            datap += optlen;
            lenleft -= optlen;
        }
    } /* while */        
    
    return 0;
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
            logmsg(LOG_ERR, "couldn't exec(): %s\nexiting...\n", strerror(localerrno));
            exit(1);
        }
    } /* child */

    return 0;
}

/* Comparison function for qsort(). Sort on arrival time. */
static int compare(const void *first, const void *second)
{
    const struct resolvdns *res1;
    const struct resolvdns *res2;

    res1 = first;
    res2 = second;
        
    if (res1->arrived < res2->arrived)
    {
        return -1;
    }
    else if (res1->arrived == res2->arrived)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

/*
 * Write the addresses in of the recursive DNS server in a file.
 */ 
static void writeresolv(struct resolvdns resolv[])
{
    int filefd;
    char buf[NSADDRSIZE];
    int i;

    if (-1 == (filefd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644)))
    {
        logmsg(LOG_ERR, "couldn't open resolv.conf file %s\n", filename);
        goto bad;
    }

    qsort(resolv, MAXNS , sizeof (struct resolvdns), compare);
    
    for (i = 0; i < MAXNS; i ++)
    {
        char srcaddrstr[INET6_ADDRSTRLEN];          

        if (0 != resolv[i].expire)
        {
            if (NULL == inet_ntop(AF_INET6, &resolv[i].addr,
                                  srcaddrstr, INET6_ADDRSTRLEN))
            {
                logmsg(LOG_ERR, "Couldn't convert IPv6 address to "
                       "string\n");
            }
        
            if (-1 == snprintf(buf, NSADDRSIZE, "nameserver %s\n",
                               srcaddrstr))
            {
                perror("asprintf");
                goto bad;
            }
        }
        
        if (-1 == write(filefd, buf, strlen(buf)))
        {
            perror("write");
            goto bad;
        }

    } /* for */

bad:
    close(filefd);
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
    for (; byte != max; row = byte)
    {
        /* Print byte offset. */
        printf("%07x ", row - buf);

        for (byte = row; byte != max && byte != (row + 16); byte ++)
        {
            printf("%02x ", *byte);
        }

        (void)putchar('\n');
    } /* Outer for */
}

static void printhelp(void)
{
    fprintf(stderr, "Usage: %s [-v [-v] [-v]] [-f filename] [-u user] "
            " [-s script] [-p pidfile ]\n", progname);

    fprintf(stderr, "-f filename gives the filename the DNS resolving address "
            "is written to. Default is ./resolv.conf.\n");
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
        childcare = 1;
    }
}

/*
 * Return the time of the resolver address with the least time to
 * live left.
 */
static time_t resolvttl(struct resolvdns resolv[])
{
    time_t least = 0;
    int i;
    
    for (i = 0; i < MAXNS; i ++)
    {
        if (0 != resolv[i].expire)
        {
            if (0 == least || resolv[i].expire < least)
            {
                least = resolv[i].expire;
            }
        }
    }
    
    return least;
}

/*
 * Add new resolver.
 */
static void addresolver(struct resolvdns resolver, struct resolvdns resolv[])
{
    struct timeval now;
    int i;
    int added = 0;
    int index = -1;
    time_t old_time = 0;
    
    if (-1 == gettimeofday(&now, NULL))
    {
        logmsg(LOG_ERR, "Couldn't get current time. Can't set expire time.\n");
        now.tv_sec = 0;
    }

    /*
     * Look for identical resolver, if none, look for free slot, if
     * not, lose the oldest and overwrite that.
     */
    for (i = 0; i < MAXNS; i ++)
    {
        if (0 == memcmp(&resolver.addr, &resolv[i].addr, sizeof (resolver.addr)))
        {
            index = i;
            added = 1;
            break;
        }

    }

    if (!added)
    {
        /* No identical found. Looking for free slots... */
        for (i = 0; i < MAXNS; i ++)
        {
            if (0 == resolv[i].expire)
            {
                /* Free slot. */
                index = i;
                added = 1;
                break;            
            }
        }
    }

    if (!added)
    {
        /* No free slots. Find oldest resolver and replace it. */
        for (i = 0; i < MAXNS; i ++)
        {
            if (-1 == index || resolv[i].arrived < old_time)
            {
                index = i;
                old_time = resolv[i].arrived;

            }
        }
    }

    /* Copy data. */
    resolv[index] = resolver;
    resolv[index].expire += now.tv_sec;
    
    if (verbose > 1)
    {
        char srcaddrstr[INET6_ADDRSTRLEN];          

        if (NULL == inet_ntop(AF_INET6, &resolver.addr,
                              srcaddrstr, INET6_ADDRSTRLEN))
        {
            logmsg(LOG_ERR, "Couldn't convert IPv6 address to "
                   "string\n");
        }
        else
        {
            printf("Added resolver %s, if %s, ttl %d seconds.\n", srcaddrstr,
                   resolver.ifname, (int)resolver.expire);
        }
    } /* if verbose */

}

/*
 * Check for expired DNS resolvers.
 */ 
static int expireresolv(struct resolvdns resolv[])
{
    int i;
    int expired = 0;
    struct timeval now;

    if (-1 == gettimeofday(&now, NULL))
    {
        logmsg(LOG_ERR, "Couldn't get current time. Can't expire.\n");
        return 0;
    }
    
    for (i = 0; i < MAXNS; i ++)
    {
        if (0 != resolv[i].expire)
        {
            if (resolv[i].expire <= now.tv_sec)
            {
                resolv[i].expire = 0;
                expired = 1;

                if (verbose > 1)
                {
                    char srcaddrstr[INET6_ADDRSTRLEN];          

                    if (NULL == inet_ntop(AF_INET6, &resolv[i].addr,
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
        } /* if not unset */
    } /* for */

    return expired;
}

/*
 * Reset all resolvers.
 */
static void resetresolv(struct resolvdns resolv[])
{
    int i;

    for (i = 0; i < MAXNS; i ++)
    {
        resolv[i].expire = 0;
    }
}

/*
 * Write a file with the current process ID.
 *
 * Returns 0 on success.
 */ 
int mkpidfile(uid_t owner, gid_t group)
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
    struct resolvdns resolvers[MAXNS]; /* Our resolvers. */
    char ifname[IFNAMSIZ];              /* Name of local interface. */
        
    progname = argv[0];

    /* Install signal handler to deal with death of child processes. */
    sigact.sa_flags = 0;
    sigact.sa_handler = sigcatch;
    sigaction(SIGCHLD, &sigact, NULL);
    
    /* Reset resolvers. */
    resetresolv(resolvers);
    
    while (1)
    {
        ch = getopt(argc, argv, "f:s:p:u:vV");
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
        }
    } /* while */
    
    if (-1 == (sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)))
    {
        logmsg(LOG_ERR, "Error from socket(). Terminating.\n");
        exit(1);
    }

    /* Get user information. */
    if (NULL == (pw = getpwnam(user)))
    {
        logmsg(LOG_ERR, "couldn't find user '%s'.\n", user);
        exit(1);
    }

    /* Write our pid to a file. */
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
                 
    /* Main loop. */
    for (progdone = 0; !progdone; )
    {
        int status;
        int newresolv = 0;
        struct timeval tv;
        struct timeval now;

        /* Figure out when to wake up. */
        if (-1 == gettimeofday(&now, NULL))
        {
            logmsg(LOG_ERR, "Couldn't get current time.\n");
            now.tv_sec = 0;
            now.tv_usec = 0;
        }

        tv.tv_sec = resolvttl(resolvers);
        tv.tv_usec = 0;        
        if (0 != tv.tv_sec && 0!= now.tv_sec)
        {
            tv.tv_sec -= now.tv_sec;
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
                if (0 == handle_icmp6(sock, resolvers, ifname))
                {
                    newresolv = 1;
                }
                
            } /* sock */
        } /* if found */

        /* Check for expired DNS servers. */
        if (expireresolv(resolvers))
        {
            /* Some resolvers expired. Maybe do something. */
            newresolv = 1;
        }

        if (newresolv)
        {
            /* Write address(es) to file. */        
            if (verbose > 0)
            {
                printf("Now writing addresses to file %s.\n", filename);
            }
            writeresolv(resolvers);

            /* Call external script, if any. */
            (void)exithook(filename, ifname);

            newresolv = 0;
        }
        
        /* Reap any zombie exit hook script(s) we might have. */
        if (childcare)
        {
            while (-1 != waitpid(-1, &status, WNOHANG))
                ;
            childcare = 0;
        }

    } /* for */

    logmsg(LOG_INFO, "Terminating.\n");
    
    exit(0);
}
