#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

struct sockaddr_in connectToService(int portNum, int* clientSocket){
  int nBytes;
  struct sockaddr_in serverAddr;

  /*Create UDP socket*/
  *clientSocket = socket(PF_INET, SOCK_DGRAM, 0);

  /*Configure settings in address struct*/
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(portNum);
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

  return serverAddr;
}
	   
int main(int argc, char **argv){
  int udpSocket, nBytes;
  char buffer[512];
  char result[1024];
  int offset = 0;
  struct sockaddr_in serverAddr;
  struct sockaddr_storage serverStorage;
  socklen_t addr_size;

  /*Create UDP socket*/
  udpSocket = socket(PF_INET, SOCK_DGRAM, 0);

  /*Configure settings in address struct*/
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(1111);
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

  /*Bind socket with address struct*/
  bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

  /*Initialize size variable to be used later on*/
  addr_size = sizeof serverStorage;

  int i;
  for(i = 1; i < argc; i++){
    // Get the update service to update the database
    printf("Requesting Database Update....\n");
    int updateSocket;
    struct sockaddr_in updateAddr = connectToService(2222, &updateSocket);
    socklen_t update_addr_size = sizeof updateAddr;
    sendto(updateSocket, "Update", 6, 0, (struct sockaddr *)&updateAddr, update_addr_size);
    nBytes = recvfrom(updateSocket, buffer, 512, 0, NULL, NULL);
    printf("%s\n",buffer);
  
    // Send filename to the file read service
    printf("Getting contents of the file %s....\n", argv[1]);
    int readSocket;
    struct sockaddr_in readAddr = connectToService(3333, &readSocket);
    socklen_t read_addr_size = sizeof readAddr;
    nBytes = sizeof(argv[1]);
    sendto(readSocket, argv[1], nBytes, 0, (struct sockaddr *)&readAddr, read_addr_size);
    nBytes = recvfrom(readSocket, buffer, 512, 0, NULL, NULL);
    if(nBytes < 0){
      printf("Unable to read file from the file_read service\n"); 
    }
    else{
      printf("Received %d bytes of data from the file_read service\n", nBytes);
      buffer[nBytes] = '\0';
    }


    // Send the contents of the file to the scan service
    printf("Scanning for viruses....\n");
    int filesize = nBytes;
    int scanSocket;
    struct sockaddr_in scanAddr = connectToService(4444, &scanSocket);
    socklen_t scan_addr_size = sizeof scanAddr;
    nBytes = sendto(scanSocket, argv[i], nBytes, 0, (struct sockaddr *)&scanAddr, scan_addr_size);
    if(nBytes < filesize){
      printf("Unable to send the file contents to the scanning service\n");
    }
    else{
      printf("Successfully sent the %d bytes to the scanning service\n", nBytes);
    }
    nBytes = recvfrom(scanSocket, buffer, 512, 0, NULL, NULL);
    if(nBytes < 0){
      printf("Unable to receive the scan results\n");
    }
    else{
      if(buffer[0] == '1'){
	offset = sprintf(result+offset, "%s - infected\n", argv[i]);
      }
      else
	offset = sprintf(result+offset, "%s - clean\n", argv[i]);
    }
  }
  printf("%s", result);
  return 0;
}
