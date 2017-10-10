/*
** server.c -- a stream socket server 
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <fcntl.h>
#include <seccomp.h>

#define PORT "3490"  // the port users will be connecting to


#define BACKLOG 10	 // how many pending connections queue will hold
#define MAXDATASIZE 100


void sigchld_handler(int s)
{
	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int fsize(FILE *fp){
    int prev=ftell(fp);
    fseek(fp, 0L, SEEK_END);
    int sz=ftell(fp);
    fseek(fp,prev,SEEK_SET); //go back to where we were
    return sz;
}

int main(void)
{

  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  
	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;
	char buf[MAXDATASIZE];
	int numbytes;
	//off_t offset = 0;
	int fd;
	struct stat stat_buf;
	int rc;
	char file_size[256];
	int offset;
    	int remain_data;
	int sent_bytes = 0;
	
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	printf("server: waiting for connections...\n");

	while(1) {  // main accept() loop
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),
			s, sizeof s);
		printf("server: got connection from %s\n", s);
		
		if ((numbytes = recv(new_fd, buf, MAXDATASIZE-1, 0)) == -1) {
			perror("recv");
		}
		buf[numbytes] = '\0';

		printf("server: received '%s'\n",buf);
		char gets1[]= "get1";
		char getsize1[] = "getsize1";
		char gets2[]= "get2";
		char getsize2[] = "getsize2";
		
		if(strncmp(gets1, buf,4)==0 || strncmp(getsize1, buf,8)==0)
			fd = open("publicfile.txt", O_RDONLY);
		else{
		  fd = open("secretfile.txt", O_RDONLY);
		  /**********************************************************/
		  //Deploying the filters
		  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(sendfile), 4,
				   SCMP_A0(SCMP_CMP_EQ, new_fd),
				   SCMP_A1(SCMP_CMP_EQ, fd),
				   SCMP_A2(SCMP_CMP_EQ, (scmp_datum_t)&offset),
				   SCMP_A3(SCMP_CMP_EQ, MAXDATASIZE-1));
		  seccomp_load(ctx);
      	        /***********************************************************/
		}
		
		if (fd == -1) {
			fprintf(stderr, "unable to open '%s'\n", "testfile");
			exit(1);
		}
		
		/* get the size of the file to be sent */
		fstat(fd, &stat_buf);
		
				
		//check if the command from client is get or getsize
		if (strncmp(getsize1, buf,8)==0 || strncmp(getsize2, buf,8)==0 ){
			sprintf(file_size, "%d", stat_buf.st_size);
			if (send(new_fd, file_size, sizeof(file_size), 0) == -1)
				perror("send");
			//close(sockfd);
			close(new_fd);
			//exit(0);
		}
		//if command is get , then send the file
		if (strncmp(gets1, buf ,5)==0 || strncmp(gets2, buf ,5)==0){
			
			sprintf(file_size, "%d", stat_buf.st_size);
			
			if (send(new_fd, file_size, sizeof(file_size), 0) == -1)
				perror("send");
			/* copy file using sendfile */
			offset = 0;
			remain_data = stat_buf.st_size;
			/* Sending file data */
			while (((sent_bytes = sendfile(new_fd, fd, &offset, MAXDATASIZE-1)) > 0) && (remain_data > 0))
			{
               			fprintf(stdout, "1. Server sent %d bytes from file's data, offset is now : %d and remaining data = %d\n", sent_bytes, offset, remain_data);
                		remain_data -= sent_bytes;
                		fprintf(stdout, "2. Server sent %d bytes from file's data, offset is now : %d and remaining data = %d\n", sent_bytes, offset, remain_data);
			}

			fprintf(stderr, "Value of errno: %d\n", errno);
			//close(sockfd);
			close(new_fd);
			//exit(0);
		}

		
		//close(new_fd);  
	}

	return 0;
}


