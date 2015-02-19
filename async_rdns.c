/* 
   async_rdns: 
   A tool for looking up the rDNS for IP address ranges and CIDR blocks
 
   Requires UDNS, a stub DNS resolver library allowing asynchronous lookups

   A lot of code was borrowed from: 
     ex-rdns.c - a file distributed with UDNS
     prips - A tool for printing ranges of IP addresses 

*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <udns.h>

#ifndef HAVE_UINT32_T
#ifdef INT32_T
typedef unsigned INT32_T uint32_t;
#else
typedef unsigned int uint32_t;
#endif
#endif

void usage(char *prog);
uint32_t numberize(const char *addr);
const char *denumberize(uint32_t addr);
uint32_t add_offset(const char *addr, int offset);
static const char *n2ip(const unsigned char *c);

static int curq;

static void dnscb(struct dns_ctx *ctx, struct dns_rr_ptr *rr, void *data) {

    const char *ip = n2ip((unsigned char *)&data); 
    
    int i;
    char *err_msg;
    --curq;
    printf("%s\t", ip);

    if (rr) {
        for(i = 0; i < rr->dnsptr_nrr; ++i)
            printf("%s\n", rr->dnsptr_ptr[i]);
        /* putchar('\n'); */
        free(rr);

    } else {

        switch(dns_status(ctx)) {
        
            /* ERROR: NOERROR */
            case DNS_E_TEMPFAIL:
                err_msg = "TEMPFAIL";
                break;

            case DNS_E_PROTOCOL:
                err_msg = "PROTOERR";
                break;
 
            case DNS_E_NXDOMAIN:
                err_msg = "NXDOMAIN";
                break;
          
            case DNS_E_NODATA:
                err_msg = "NODATA";
                break;

            case DNS_E_NOMEM:
                err_msg = "NOMEM";
                break;
 
            case DNS_E_BADQUERY:
                err_msg = "BADQUERY";
                break;

            default:
                err_msg = "NOERROR"; 

        }
        
        printf("%s\n", err_msg);
    }     
}

int main(int argc, char **argv) {

    int c;
    time_t now;
    int maxq = 10;
    struct pollfd pfd;
    uint32_t start = 0, end = 0, current;
    int increment = 1; /* Standard incrementer is one */
    char *prefix, *offset; 
    const char *readable;
    
    if (dns_init(NULL, 1) < 0) {
        fprintf(stderr, "unable to initialize dns library\n");
        return 1;
    }
    
    while((c = getopt(argc, argv, "i:m:r")) != EOF) switch(c) {

        case 'm':
            maxq = atoi(optarg); 
            break;

        case 'r':
            dns_set_opt(0, DNS_OPT_FLAGS,
            dns_set_opt(0, DNS_OPT_FLAGS, -1) | DNS_NORD);
            break;

        case 'i':
            if((increment = atoi(optarg)) < 1) {
                fprintf(stderr, "%s: increment must be a positive integer\n", argv[0]);
                exit(1);
            }
            break;
        case '?':
            usage(argv[0]);
            exit(1);
    }
    
    switch(argc - optind) {
    
        case 1: /* looks like a CIDR */

            prefix = strtok(argv[optind], "/");
              
            if((offset = strtok(NULL, "/"))) {

                start = numberize(prefix);

                if(start == (uint32_t)-1) {
                    fprintf(stderr, "%s: bad IP address\n", argv[0]);
                    exit(1);
                }

                end = add_offset(prefix, atoi(offset));

            } else {
                usage(argv[0]);
                exit(1);
            }

            break;

        case 2: /* looks like a start and end address */
        
            start = numberize(argv[optind]);
            end = numberize(argv[optind+1]);

            if(start == (uint32_t)-1 || end == (uint32_t)-1) {
                fprintf(stderr, "%s: bad IP address\n", argv[0]);
                exit(1);
            }

            break;

        default:

            usage(argv[0]);
            exit(1);
    }
    
    if (start > end) {
        fprintf(stderr, "%s: start address must be smaller than end address\n", argv[0]);
        exit(1);
    }
    
    pfd.fd = dns_sock(0);
    pfd.events = POLLIN;
    now = time(NULL);
    c = optind;
    
    for(current = start; current <= end; current += increment) { 
        
        union { struct in_addr a; void *p; } pa;
        readable = denumberize(current);
        /* printf("%s ", readable); */

        if (dns_pton(AF_INET, readable, &pa.a) <= 0)
            fprintf(stderr, "%s: invalid address\n", readable);
        else if (dns_submit_a4ptr(0, &pa.a, dnscb, pa.p) == 0)
            fprintf(stderr, "%s: unable to submit query: %s\n", current, dns_strerror(dns_status(0)));
        else
            ++curq;
        
        if (curq) {
            c = dns_timeouts(0, -1, now);
            c = poll(&pfd, 1, c < 0 ? -1 : c * 1000);
            now = time(NULL);

            if (c)
                dns_ioevent(0, now);
        }
    }
    return 0;
}

void usage(char *prog) {
    fprintf(stderr, "usage: %s [options] <start end | CIDR block>\n-i <x>  set the increment to 'x'\n-m set max limit for queue\n\n", prog);
}

/**********************************************/
/* Turn an IP address in dotted decimal into  */ 
/* a number.  This function also works  for   */
/* partial addresses.                         */
/**********************************************/
uint32_t numberize(const char *addr) {

    uint32_t sin_addr;
    int retval;

    retval = inet_pton(AF_INET, addr, &sin_addr);

    /* invalid address or error in inet_pton() */
    if(retval == 0 || retval == -1)
        return (uint32_t)-1; 

    return ntohl(sin_addr); 
}

/**********************************************/
/* Converts an IP address into dotted decimal */
/* format.  Note that this function cannot be */
/* used twice in one instruction (e.g. printf */
/* ("%s%s",denumberize(x),denumberize(y)));   */
/* because the return value is static.        */
/**********************************************/
const char *denumberize(uint32_t addr) {

    static char buffer[16]; /* length of ipv4 */
    uint32_t addr_nl = htonl(addr);
 
    if(!inet_ntop(AF_INET, &addr_nl, buffer, sizeof(buffer)))
        return NULL;

     return buffer;
}

/***********************************************/
/* Takes offset (number of bits from the left  */ 
/* of addr) and subtracts it from the number   */
/* of possible bits.  The number of possible   */
/* bits is the number of bits left for hosts.  */
/* We then return last host address.           */
/***********************************************/
uint32_t add_offset(const char *addr, int offset) {
  
    uint32_t naddr;

    if(offset > 32 || offset < 0) {
        fprintf(stderr, "CIDR offsets are between 0 and 32\n");
        exit(1);
    }

    naddr = numberize(addr);

    if((naddr << offset) != 0) {
        fprintf(stderr, "CIDR base address didn't start at subnet boundary\n");
        exit(1);
    }

    return (uint32_t)(1 << (32 - offset)) + naddr -1;

}

static const char *n2ip(const unsigned char *c) {
    static char b[sizeof("255.255.255.255")];
    sprintf(b, "%u.%u.%u.%u", c[0], c[1], c[2], c[3]);
    return b;
}

