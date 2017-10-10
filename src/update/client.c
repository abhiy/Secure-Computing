/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define PORT "3490" // the port client will be connecting to 

#define MAXDATASIZE 5 // max number of bytes we can get at once 

#define FILENAME "foo.txt"

//Toggle between any of these two commands : get and getsize
//#define COMMAND 0 // getsize
#define COMMAND 1 // get

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	int sockfd, numbytes;  
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	int file_size;
	FILE *received_file;
	int remain_data = 0;
	ssize_t len;

	if (argc != 3) {
	    fprintf(stderr,"usage: client hostname\n");
	    exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure


	
	
	int op = atoi(argv[2]);
	switch(op){
		case 1 : //Getsize publicfile.txt

			if (send(sockfd, "getsize1", 13, 0) == -1)
                perror("send");

			if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
				perror("recv");
				exit(1);
			}
			buf[numbytes] = '\0';
			printf("client: received. no of bytes :'%s'\n",buf);
			break;
			
		case 2: //Get  publicfile.txt
			if (send(sockfd, "get1", 13, 0) == -1)
                perror("send");

			if(recv(sockfd, buf, MAXDATASIZE-1, 0) == -1){
				perror("recv");
				exit(1);
			}
			file_size = atoi(buf);
			//fprintf(stdout, "\nFile size : %d\n", file_size);

			received_file = fopen(FILENAME, "w");
			if (received_file == NULL)
			{
					fprintf(stderr, "Failed to open file foo \n");

					exit(1);
			}

			remain_data = file_size;

			while (((len = recv(sockfd, buf, MAXDATASIZE-1, 0)) > 0) && (remain_data > 0))
			{
					fwrite(buf, sizeof(char), len, received_file);
					remain_data -= len;
					fprintf(stdout, "Receive %d bytes and we hope :- %d bytes\n", len, remain_data);
			}
			break;
		case 3 : //Getsize secretfilefile.txt

			if (send(sockfd, "getsize2", 13, 0) == -1)
                perror("send");

			if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
				perror("recv");
				exit(1);
			}
			buf[numbytes] = '\0';
			printf("client: received. no of bytes :'%s'\n",buf);
			break;
			
		case 4: //Get  secretfile.txt
			if (send(sockfd, "get2", 13, 0) == -1)
                perror("send");

			if(recv(sockfd, buf, MAXDATASIZE-1, 0) == -1){
				perror("recv");
				exit(1);
			}
			file_size = atoi(buf);
			//fprintf(stdout, "\nFile size : %d\n", file_size);

			received_file = fopen(FILENAME, "w");
			if (received_file == NULL)
			{
					fprintf(stderr, "Failed to open file foo \n");

					exit(1);
			}

			remain_data = file_size;

			while (((len = recv(sockfd, buf, MAXDATASIZE-1, 0)) > 0) && (remain_data > 0))
			{
					fwrite(buf, sizeof(char), len, received_file);
					remain_data -= len;
					fprintf(stdout, "Receive %d bytes and we hope :- %d bytes\n", len, remain_data);
			}
			break;
	
	}

	close(sockfd);

	return 0;
}


