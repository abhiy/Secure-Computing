#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

int readFile(char buffer[]){
  FILE* fp;
  fp = fopen(buffer, "r");
  fseek(fp, 0, SEEK_END);
  long fpsize = ftell(fp);
  fseek(fp, 0, SEEK_SET);  //same as rewind(f);

  fgets(buffer, fpsize, fp);
  fclose(fp);

  return fpsize;
}

int main(){
  int udpSocket, nBytes;
  char buffer[512];
  struct sockaddr_in serverAddr;
  struct sockaddr_storage serverStorage;
  socklen_t addr_size;
  int i;

  /*Create UDP socket*/
  udpSocket = socket(PF_INET, SOCK_DGRAM, 0);

  /*Configure settings in address struct*/
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(3333);
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

  /*Bind socket with address struct*/
  int ok = bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

  if(ok != 0){
    printf("Error in binding to the port 3333: %s\n", strerror(errno));
  }

  /*Initialize size variable to be used later on*/
  addr_size = sizeof serverStorage;

  while(1){
    // Waits to hear from main service
    nBytes = recvfrom(udpSocket, buffer, 1024, 0, (struct sockaddr *)&serverStorage, &addr_size);
    buffer[nBytes] = '\0';
    printf("Received request to read the file: %s\n", buffer);
    nBytes = readFile(buffer);
    nBytes = sendto(udpSocket, buffer, nBytes, 0, (struct sockaddr *)&serverStorage, addr_size);
    if(nBytes < 0){
      printf("Unable to send the file contents to the main service \n");
    }
    else{
      printf("Sent %d bytes to the main service\n", nBytes);
    }
  }
  return 0;
}
