/* 
 * This program does asynchronous bulk lookups with the firedns library,
 * (available as a package under Debian derived systems at least).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <firestring.h>
#include <firedns.h>
#include <regex.h>

/* do_lookup: perform lookup, then print results alongside inputted line */
void do_lookup( char * line, char * match) {

    int fd;
    fd_set s;
    int n; 
    struct timeval tv;
    char *m;
    struct in_addr *addr4;

    addr4 = firedns_aton4(match);
    if (addr4 == NULL) {
    	firestring_fprintf(stdout,"%s\t(null)\n", line);
    	return;
    }

    fd = firedns_getname4(addr4);
    if (fd == -1)
    	return;

    tv.tv_sec = 5;
    tv.tv_usec = 0;

    FD_ZERO(&s);
    FD_SET(fd,&s);

    n = select(fd + 1,&s,NULL,NULL,&tv);
    m = firedns_getresult(fd);

    firestring_fprintf(stdout,"%s\t%s\n", line, m);

}

/* regexp: return the match part */
char *regexp (char *string) {    

    int begin, end;
    int i, w = 0; 
    int length;                 
    char *word = NULL;
    regex_t regex;
    regmatch_t match;

    regcomp(&regex,"[0-9]+.[0-9]+.[0-9]+.[0-9]+",REG_EXTENDED);

    if ((regexec(&regex,string,1,&match,0)) == 0) {
    
        begin = match.rm_so;
        end = match.rm_eo;
    
        length = end - begin;
        word = malloc(length+1);
    
        for (i = begin; i < end; i++) {
            word[w] = string[i];
            w++; 
        }
        /* word[w] = 0; */
        word[w] = '\0';
    }

    regfree(&regex);
    return word; 
}

/* main: get the input, lop it off, search for match */
int main() {

    char line[256];

    while (fgets(line, 256, stdin) != NULL) {

        line[strlen(line)-1] = '\0';

        char *match = regexp(line);

        if (match) {
            do_lookup(line, match);
        } else {
            printf("%s\n", line);
        }
    }

    return 0;
}
