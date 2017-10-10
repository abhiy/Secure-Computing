/************* UDP SERVER CODE *******************/

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

  //printf("reached here !!\n");
  
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((rv = getaddrinfo("localhost", PORT, &hints, &servinfo)) != 0) {
    //printf("reached here !!\n");  
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
  //fclose(fp);
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
  bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

  /*Initialize size variable to be used later on*/
  addr_size = sizeof serverStorage;

  FILE* fp;
  fp = fopen("../../db/threat", "a");
  if(fp == NULL)
    printf("Can't open the threat file");
  
  while(1){
    /* Try to receive any incoming UDP datagram. Address and port of 
       requesting client will be stored on serverStorage variable */
    // Waits to hear from main service
    nBytes = recvfrom(udpSocket, buffer, 1024, 0, (struct sockaddr *)&serverStorage, &addr_size);
    printf("Received request: %s\n", buffer);
    updateDatabase(fp);
    sendto(udpSocket, "Update Completed", 17, 0, (struct sockaddr *)&serverStorage, addr_size);
  }

  return 0;
}
