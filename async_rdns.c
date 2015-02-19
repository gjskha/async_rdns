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
#warning Using the Makefile-defined INT32_T as int
#else
typedef unsigned int uint32_t;
#warning Just guessing, using unsigned int for uint32_t
#endif
#endif

void usage(char *prog);
int set_exceptions(char *exp, int octet[4][256]);
int except(uint32_t *current, int octet[4][256]);
uint32_t numberize(const char *addr);
const char *denumberize(uint32_t addr);
uint32_t add_offset(const char *addr, int offset);
static void fill(int octet[4][256]);

static int curq;

static void dnscb(struct dns_ctx *ctx, struct dns_rr_ptr *rr, void *data) {
int i;
--curq;
if (rr) {
for(i = 0; i < rr->dnsptr_nrr; ++i)
printf("%s", rr->dnsptr_ptr[i]);
/* putchar('\n'); */
free(rr);
}
else
/* fprintf(stderr, "%s\n", dns_strerror(dns_status(ctx))); */
/* fprintf(stderr, "%d\n", dns_status(ctx)); */
fprintf(stderr, "%d", dns_status(ctx));

/*
DNS_E_TEMPFAIL

temporary error, the resolver nameserver was not able to process our query or timed out.

DNS_E_PROTOCOL

protocol error, a nameserver returned malformed reply.

DNS_E_NXDOMAIN

the domain name does not exist.

DNS_E_NODATA

there is no data of requested type found.

DNS_E_NOMEM

out of memory while processing request.

DNS_E_BADQUERY

*/

}

int main(int argc, char **argv) {

    int c;
    time_t now;
    int maxq = 10;
    struct pollfd pfd;
    uint32_t start = 0, end = 0, current;
    int octet[4][256]; /* Holds all of the exceptions if -e is used */
    int increment = 1; /* Standard incrementer is one */
    char *prefix, *offset, *readable;
    int exception_flag = 0; /* If one, check for exclusions */
    
    if (dns_init(NULL, 1) < 0) {
        fprintf(stderr, "unable to initialize dns library\n");
        return 1;
    }
    
    while((c = getopt(argc, argv, "i:e:m:r")) != EOF) switch(c) {

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
        
        case 'e':
            set_exceptions(optarg, octet);
            exception_flag = 1;
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
    
    /* printf("%d,%d", start, end); */
    
    pfd.fd = dns_sock(0);
    pfd.events = POLLIN;
    now = time(NULL);
    c = optind;
    
    for(current = start; current <= end; current += increment) 
    { if(!exception_flag || !except(&current, octet))
    {
    printf("%s\t", denumberize(current));
         
    union { struct in_addr a; void *p; } pa;
    readable = denumberize(current);
    if (dns_pton(AF_INET, readable, &pa.a) <= 0)
    /* fprintf(stderr, "%s: invalid address\n", linebuf); */
    fprintf(stderr, "%s: invalid address\n", readable);
    else if (dns_submit_a4ptr(0, &pa.a, dnscb, pa.p) == 0)
    fprintf(stderr, "%s: unable to submit query: %s\n",
    current, dns_strerror(dns_status(0)));
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
    }
    return 0;
}

void usage(char *prog) {
    fprintf(stderr, "usage: %s [options] <start end | CIDR block>\n-i <x>  set the increment to 'x'\n-e <x.x.x,x.x> e.g. -e ..4. will not print 192.168.4.[0-255]\n-m set max limit for queue \n\n", prog);
}

/*****************************************************************/
/* This function parses the exception string and adds all of the */
/* exceptions to the proper place in the exception table.  A '.' */
/* is used to separate octets.  Numbers are separated by any non */
/* digit other than the '.', which has special meaning.          */
/*****************************************************************/
int set_exceptions(char *exp, int octet[4][256])
{
size_t i;
int excludeind = 0, bufferind = 0, octind = 0;
char buffer[4];

fill(octet);
for(i = 0; i < strlen(exp) + 1; i++)
{
if( isdigit(exp[i]))
{
buffer[bufferind] = exp[i];
bufferind++;
assert(bufferind != 4); /* potential overflow... */
}
else
{
if(bufferind)
{
buffer[bufferind] = '\0';
octet[octind][excludeind] = atoi(buffer);
bufferind = 0;
excludeind++; 
}

if(exp[i] == '.')
{
octind++;
excludeind = 0;
}
}
}
return(0);
}

static void fill(int octet[4][256]) {

    register int i, j;
 
    for(i = 0; i < 4; i++)
        for(j = 0; j < 256; j++)
            octet[i][j] = -1;
}

/*******************************************************************/
/* Compares each octet against the list of exceptions for that     */
/* octet.  If the octet is in the list of exceptions the 'current' */
/* argument is incremented so that the 'current' variable is moved */
/* up one octet.  I hope to God this makes sense... it's late. I'm */
/* tired.                                                          */
/*******************************************************************/
int except(uint32_t *current, int octet[4][256])
{
 register int i, j;

 for(i = 0; i < 4; i++)
 {
  for(j = 0; j < 256; j++)
  {
   switch(i)
   {
   case 0:
    if((int)((*current >> 24) & 0xff) == octet[i][j])
    {
     *current += (uint32_t)(1 << 24) -1;
     return(1);
    }
    break;
   case 1:
    if((int)((*current >> 16) & 0xff) == octet[i][j])
    {
     *current += (uint32_t)(1 << 16) -1;
     return(1);
    }
    break;
   case 2:
    if((int)((*current >> 8) & 0xff) == octet[i][j])
    {
        *current += (uint32_t)(1 << 8) -1; 
                                    return(1);
    }
    break;
   case 3:
    if((int)(*current & 0xff) == octet[i][j])
                                 return(1);
    break;

   }
  }
 }
 return(0);
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
const char *denumberize(uint32_t addr)
{
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

if(offset > 32 || offset < 0)
{
fprintf(stderr, "CIDR offsets are between 0 and 32\n");
exit(1);
}

naddr = numberize(addr);
if((naddr << offset) != 0) 
{
fprintf(stderr, 
"CIDR base address didn't start at subnet boundary\n");
exit(1);
}

return (uint32_t)(1 << (32 - offset)) + naddr -1;
}
