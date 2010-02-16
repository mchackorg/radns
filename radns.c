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
 * Originally written by Michael Cardell Widerkrantz for Stickybit AB.
 * http://www.stickybit.se/
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
 * THIS SOFTWARE IS PROVIDED BY STICKYBIT AB ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL STICKYBIT AB BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#ifdef DMALLOC
#include <dmalloc.h>
#endif

#define RESOLVEFILE "./resolv.conf"

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
int progdone = 0;
int verbose = 0;

/*
 * Array of printable IPv6 addresses.
 */ 
struct straddrs
{
    char **addrbuf;
    int num; /* The number of addresses held in addrbuf. */
};
    
static void hexdump(u_int8_t *buf, u_int16_t len);
static void printhelp(void);
static void writeresolv(struct straddrs straddrs);
static void logmsg(int pri, const char *message, ...);
static void freeaddrmem(struct straddrs *addrs);
static int getaddrmem(struct straddrs *addrs, int num);

/*
 * Callback function when we get an ICMP6 message on socket sock.
 */ 
void handle_icmp6(int sock)
{
    u_int8_t buf[PACKETSIZE];   /* The entire ICMP6 message. */
    int buflen;                 /* The lenght of the ICMP6 buffer. */
    const struct nd_router_advert *ra; /* A Router Advertisement */
    const struct nd_opt_rdnss
    {
	u_int8_t nd_opt_type; /* Should be 25 (0x19) for RDNSS */
	u_int8_t nd_opt_len; /* Length: 3 (* 8 octets) if one IPv6
                                address. No of addresses = (Length -
                                1) / 2.  If less than 3, disregard.*/
        u_int16_t nd_opt_rdns_res; /* */
        u_int32_t nd_opt_rdns_life; /* The maximum time in seconds to
                                       use this from the time it was
                                       sent. */
    } *rdnss;
    u_int8_t *datap;            /* An octet pointer we use for running
                                 * through data in buf. */
    int lenleft;                /* Length left in buf, in bytes,
                                 * counting from datap. */
    struct in6_addr *addr;      /* An IPv6 address. */
    struct straddrs straddrs;   /* A list of printable IPv6 addresses. */
    struct sockaddr_in6 src;    /* Source address of RA packet. */
    socklen_t size = sizeof (struct sockaddr_in6);

    if (-1 == (buflen = recvfrom(sock, &buf, PACKETSIZE, 0,
                                 (struct sockaddr *)&src, &size)))
    {
        logmsg(LOG_ERR, "read error on raw socket\n");
        return;
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
        logmsg(LOG_INFO, "Not a Router Advertisement. Type: %d, code: %d."
                "Why did we get it?\n",
                ra->nd_ra_type, ra->nd_ra_code);
        return;
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
        char ifname[IFNAMSIZ];
        char srcaddrstr[INET6_ADDRSTRLEN];            

        if (NULL == inet_ntop(AF_INET6, &src.sin6_addr, srcaddrstr, INET6_ADDRSTRLEN))
            {
                perror("Couldn't convert IPv6 address to string");
        }
        
        printf("Received an IPv6 Router Advertisement from %s\n", srcaddrstr);

        if (NULL != if_indextoname(src.sin6_scope_id, ifname))
        {
            printf("On interface: %s\n", ifname);
        }
        else
        {
            printf("On unknown interface, index %d\n", src.sin6_scope_id);
        }

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
        return;
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
                return;
            }

            /* Move to first IPv6 address. */
            datap += sizeof (struct nd_opt_rdnss);
            lenleft -= sizeof (struct nd_opt_rdnss);
            
            if (lenleft <= 0)
            {
                /* Out of data! */
                logmsg(LOG_INFO, "RDNSS option: Out of data.\n");
                return;
            }

            /* How many addresses to DNS servers are there? */
            nr_of_addrs = (rdnss->nd_opt_len - 1) / 2;

            if (verbose > 0)
            {
                printf("%d address(es) to resolving DNS servers found.\n",
                       nr_of_addrs);
            }

            /*
             * Get an array big enough to keep all these IPv6
             * addresses in printable form.
             */
            if (0 != getaddrmem(&straddrs, nr_of_addrs))
            {
                logmsg(LOG_ERR, "Out of memory from getaddrmem\n");
                return;
            }
                
            /* Find the addresses and convert them to printable form. */
            for (i = 0; i < nr_of_addrs; i ++)
            {
                addr = (struct in6_addr *)datap;
                
                if (NULL == inet_ntop(AF_INET6, addr, straddrs.addrbuf[i],
                                      INET6_ADDRSTRLEN))
                {
                    perror("Couldn't convert IPv6 address to string");

                    /* Free the space for the addresses. */
                    freeaddrmem(&straddrs);
                    return;
                }

                if (verbose > 0)
                {
                    printf("Resolving DNS server address: %s\n",
                           straddrs.addrbuf[i]);
                }

                /* Move to next address, if any. */
                datap += sizeof (struct in6_addr);
                lenleft -= sizeof (struct in6_addr);
            } /* for */

            if (verbose > 0)
            {
                printf("Now writing addresses to file %s.\n", filename);
            }

            /* Write address(es) to file. */
            writeresolv(straddrs);

            /* Free the space for the addresses. */
            freeaddrmem(&straddrs);
        }
        else
        {
            /* Not an RDNSS option. Skip it. */
            datap += optlen;
            lenleft -= optlen;
        }
    } /* while */        
    
    return;
}

/*
 * Free all IPv6 strings and the array of pointers in addrs.
 */
static void freeaddrmem(struct straddrs *addrs)
{
    int i;

    /* Free the strings. */
    for (i = 0; i < addrs->num; i ++)
    {
        free(addrs->addrbuf[i]);
    }

    /* Free the array of pointers. */
    free(addrs->addrbuf);

    addrs->num = 0;
}

/*
 * Allocate num number of character strings with space enough to keep
 * IPv6 addressses.
 *
 * Returns 0 on success, -1 on failure.
 */ 
static int getaddrmem(struct straddrs *addrs, int num)
{
    int i;

    /* Allocate the array of pointers. */
    if (NULL == (addrs->addrbuf = malloc(num * sizeof (char *))))
    {
        printf("Out of memory\n");
        exit(0);
    }

    /* Allocate space for the strings. */
    addrs->num = 0;
    for (i = 0; i < num; i ++)
    {
        if (NULL == (addrs->addrbuf[i] = malloc(INET6_ADDRSTRLEN)))
        {
            printf("Out of memory\n");
            goto bad;
        }

        /*
         * Keep track on how many strings we have managed to allocate
         * so far.
         */
        addrs->num ++;
    }

    return 0;

bad:
    /*
     * Free all the buffers we allocated before we ran out of memory.
     */
    freeaddrmem(addrs);
    
    return -1;
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
 * Write the addresses in of the recursive DNS server in a file.
 */ 
static void writeresolv(struct straddrs straddrs)
{
    int filefd;
    char buf[NSADDRSIZE];
    int i;

    if (-1 == (filefd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644)))
    {
        perror("open");
        goto bad;
    }

    for (i = 0; i < straddrs.num; i ++)
    {
        if (-1 == snprintf(buf, NSADDRSIZE, "nameserver %s\n",
                           straddrs.addrbuf[i]))
        {
            perror("asprintf");
            goto bad;
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
static void hexdump(u_int8_t *buf, u_int16_t len)
{
    u_int8_t *row; /* Pointer to rows of 16 bytes each. */
    u_int8_t *byte; /* Pointer to each byte in the row. */
    u_int8_t *max; /* Pointer to the maximum address in buf. */

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
    fprintf(stderr, "Usage: %s [-v [-v] [-v]] [-f filename]\n", progname);

    fprintf(stderr, "-f filename gives the filename the DNS resolving address "
            "is written to. Default is ./resolv.conf.\n");
    fprintf(stderr, "Repeating -v means more verbosity.\n");
    fprintf(stderr, "Use -V to get version information.\n");
}

int main(int argc, char **argv)
{
    char ch;                    /* Option character */
    int sock;               /* Raw socket file descriptor */
    struct icmp6_filter filter; /* Filter for raw socket. */
    fd_set in;
    int found;
    
    progname = argv[0];

    while (1)
    {
        ch = getopt(argc, argv, "f:i:vV");
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

    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);

    if (-1 == setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
                         sizeof(filter)))
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
        FD_ZERO(&in);
        
        FD_SET(sock, &in);
        
        found = select(sock + 1, &in, NULL, NULL, NULL);
        if (-1 == found)
        {
            perror("select");
        }
        else
        {
            if (-1 != sock && FD_ISSET(sock, &in))
            {
                handle_icmp6(sock);
            } /* sock */
        } /* if found */
    } /* for */

    logmsg(LOG_INFO, "Terminating.\n");
    
    exit(0);
}
