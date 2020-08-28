/* 
 *  async_rdns: 
 *  A tool for looking up rDNS for IP address ranges and CIDR blocks asynchronously
 *
 *  Requires UDNS, a stub DNS resolver library.
 *
 *  Some code and/or algorithms borrowed from: 
 *      ex-rdns.c - one of the files distributed with UDNS
 *      prips - A tool for printing ranges of IP addresses 
 *
 */

#include <sys/types.h>
#include <netinet/in.h> 
#include <sys/poll.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <udns.h>

#ifndef HAVE_UINT32_T
#ifdef INT32_T
typedef unsigned INT32_T uint;
#else
typedef unsigned int uint;
#endif
#endif

void usage(char *prog);
uint numberize(const char *addr);
const char* denumberize(uint addr);
uint add_offset(const char *addr, int offset);
static void dnscb(struct dns_ctx *ctx, struct dns_rr_ptr *rr, void *data);

static uint curq;

int main(int argc, char **argv) {
    time_t now;
    struct pollfd pfd;
    uint start = 0, end = 0, maxq = 10, c, current; 
    int increment = 1; 
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
            dns_set_opt(0, DNS_OPT_FLAGS, dns_set_opt(0, DNS_OPT_FLAGS, -1) | DNS_NORD);
            break;

        case 'i':
            if ((increment = atoi(optarg)) < 1) {
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
              
            if ((offset = strtok(NULL, "/"))) {

                start = numberize(prefix);

                if (start == (uint)-1) {
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

            if (start == (uint)-1 || end == (uint)-1) {
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
    c = 0;

    for(current = start; current <= end; current += increment) { 
        
        union { struct in_addr a; void *p; } pa;
	
	readable = denumberize(current); 
	
                              // src    // destination	
        if (dns_pton(AF_INET, readable, &pa.a) <= 0)
            fprintf(stderr, "%s: invalid address\n", readable);
        else 
		
	if (dns_submit_a4ptr(0, &pa.a, dnscb, pa.p) == 0)
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

/**********************************************/
/* Turn an IP address in dotted decimal into  */ 
/* a number.  This function also works  for   */
/* partial addresses.                         */
/**********************************************/
void usage(char *prog) {
    fprintf(stderr, "usage: %s [options] <start end | CIDR block>\n", prog);
    fprintf(stderr, "-i <x>  set the increment to 'x'\n");
    fprintf(stderr, "-m <y> set max limit for queue to 'y'\n\n");
}

/**********************************************/
/* Turn an IP address in dotted decimal into  */ 
/* a number.  This function also works  for   */
/* partial addresses.                         */
/**********************************************/
uint numberize(const char *addr) {

    uint sin_addr;
    int retval;

                               
    retval = dns_pton(AF_INET, addr, &sin_addr);

    if (retval == 0 || retval == -1)
        return (uint)-1; 

    return ntohl(sin_addr); 
}

/**********************************************/
/* Converts an IP address into dotted decimal */
/* format.  Note that this function cannot be */
/* used twice in one instruction (e.g. printf */
/* ("%s%s",denumberize(x),denumberize(y)));   */
/* because the return value is static.        */
/**********************************************/
const char* denumberize(uint addr) {

    static char buffer[16]; /* length of ipv4 */
    uint addr_nl = htonl(addr);

    if (!dns_ntop(AF_INET, &addr_nl, buffer, sizeof(buffer)))
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
uint add_offset(const char *addr, int offset) {
  
    uint naddr;

    if(offset > 32 || offset < 0) {
        fprintf(stderr, "CIDR offsets are between 0 and 32\n");
        exit(1);
    }

    naddr = numberize(addr);

    if((naddr << offset) != 0) {
        fprintf(stderr, "CIDR base address didn't start at subnet boundary\n");
        exit(1);
    }

    return (uint)(1 << (32 - offset)) + naddr -1;

}

static void dnscb(struct dns_ctx *ctx, struct dns_rr_ptr *rr, void *data) {

    const char *ip = denumberize(htonl((uint)data)); 
    printf("%s\t", ip);

    char *err_msg;
    --curq;

    if (rr) {
        for(int i = 0; i < rr->dnsptr_nrr; ++i)
            printf("%s\n", rr->dnsptr_ptr[i]);
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
