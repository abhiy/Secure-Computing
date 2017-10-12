#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <seccomp.h>

#define MAXDATASIZE 5
#define PORT "3490"

void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int connectToInfoServer(){
  int sockfd, numbytes;
  struct addrinfo hints, *servinfo, *p;
  int rv;
  char s[INET6_ADDRSTRLEN];
  ssize_t len;

  memset(&hints, 0, sizeof hints);

  
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((rv = getaddrinfo("localhost", PORT, &hints, &servinfo)) != 0) {  
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  // loop through all the results and connect to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
			 p->ai_protocol)) == -1) {
      perror("update_service: socket");
      continue;
    }

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      perror("update_service: connect");
      close(sockfd);
      continue;
    }

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "Failed to connect to remote server\n");
    return 2;
  }

  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
	    s, sizeof s);
  printf("update_service: connecting to remote server %s\n", s);

  freeaddrinfo(servinfo); // all done with this structure

  return sockfd;
}

void updateDatabase(FILE* fp){
  char buf[MAXDATASIZE];
  int remain_data, len;
  int nBytes;
  int sockfd = connectToInfoServer();
  remain_data = 4;
  while (((len = recv(sockfd, buf, MAXDATASIZE-1, 0)) > 0) && (remain_data > 0))
    {
      //fwrite(buf, sizeof(char), len, received_file);
      remain_data -= len;
      fprintf(stdout, "Received %d byte string and we hope : %d bytes more\n", len, remain_data);
    }
  buf[MAXDATASIZE-1] = '\0';
  if(fputs(buf, fp) < 0){
    printf("Error in updating the database file\n");
  }
  else{
    printf("Wrote %s to the file\n", buf);
  }
}  

int main(){
  int udpSocket, nBytes;
  char buffer[1024];
  struct sockaddr_in serverAddr;
  struct sockaddr_storage serverStorage;
  socklen_t addr_size;

  /*Create UDP socket*/
  udpSocket = socket(PF_INET, SOCK_DGRAM, 0);

  /*Configure settings in address struct*/
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(2222);
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

  /*Bind socket with address struct*/
  int ok = bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
  
  if(ok != 0){
    printf("Error in binding to the port 2222: %s\n", strerror(errno));
    exit(0);
  }
  
  /*Initialize size variable to be used later on*/
  addr_size = sizeof serverStorage;

  FILE* fp;
  fp = fopen("/home/aby/Sem-1/Security/hw-2/Project/db/threat", "a");
  if(fp == NULL){
    printf("Error in opening the virus signature file: %s\n", strerror(errno));
    exit(0);
  }
  int fd = fileno(fp);
  
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);

  // Creating a whitelist
  //seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 1, SCMP_A0(SCMP_CMP_EQ, udpSocket));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 1, SCMP_A0(SCMP_CMP_EQ, udpSocket));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1));

  //seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, fd));
  //seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, 1));

  //seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, fd));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 1, SCMP_A0(SCMP_CMP_EQ, fd));

  // Need to be more permissive to allow connection over IP sockets :(
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_EQ, O_RDONLY|O_CLOEXEC));                                                         
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);


  seccomp_load(ctx);
  while(1){
    /* Try to receive any incoming UDP datagram. Address and port of 
       requesting client will be stored on serverStorage variable */
    // Waits to hear from main service
    nBytes = recvfrom(udpSocket, buffer, 1024, 0, (struct sockaddr *)&serverStorage, &addr_size);
    printf("Received request: %s\n", buffer);
    updateDatabase(fp);
    sendto(udpSocket, "Update Completed", 17, 0, (struct sockaddr *)&serverStorage, addr_size);
  }
  seccomp_release(ctx);
  return 0;
}
