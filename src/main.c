#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

typedef enum {update, read, scan} serviceType;
static char* enumStrings[]={"update", "read", "scan"};
int checkStatus(serviceType service){
  int ret = 0;
  int udpSocket;
  int portNum;
  struct sockaddr_in serverAddr;
  struct sockaddr_storage serverStorage;
  socklen_t addr_size;

  /*Create UDP socket*/
  udpSocket = socket(PF_INET, SOCK_DGRAM, 0);
  /*To ensure that socket is realease immediately after close*/
  int iSetOption = 1;
  setsockopt(udpSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&iSetOption, sizeof(iSetOption));
  
  /*Configure settings in address struct*/
  serverAddr.sin_family = AF_INET;
  
  switch(service) {
  case update : portNum = 2222; break;
  case read : portNum = 3333; break;
  case scan: portNum = 4444; break;
  }
  
  serverAddr.sin_port = htons(portNum);
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

  printf("Checking if the service \"%s\" is running at port number %d\n", enumStrings[service], portNum); 
  /*Bind socket with address struct*/
  int ok = bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

  if(ok == 0){
    printf("The service \"%s\" is NOT running\n", enumStrings[service]);
    ret = 0;
    close(udpSocket);
  }
  else{
    printf("The service \"%s\" is running\n", enumStrings[service]);
    ret = 1;
  }
  return ret;
}



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

void getDatabaseUpdated(char buffer[]){
  int ok = checkStatus(update);
  pid_t child_pid;
  if(!ok){
    child_pid = fork();
    if(child_pid == 0){
      system("./update/update");
      exit(0);
    }
    printf("Update service started with pid %d\n", child_pid);
  }
  printf("Requesting Database Update....\n");
  int updateSocket;
  struct sockaddr_in updateAddr = connectToService(2222, &updateSocket);
  socklen_t update_addr_size = sizeof updateAddr;
  sendto(updateSocket, "Update", 6, 0, (struct sockaddr *)&updateAddr, update_addr_size);
  int nBytes = recvfrom(updateSocket, buffer, 512, 0, NULL, NULL);
  buffer[nBytes] = '\0';
  printf("%s\n",buffer);
  return;
}

int readFile(char buffer[], char* arg){
  printf("Getting contents of the file %s....\n", arg);
  int readSocket;
  struct sockaddr_in readAddr = connectToService(3333, &readSocket);
  socklen_t read_addr_size = sizeof readAddr;
  int nBytes = sizeof(arg);
  sendto(readSocket, arg, nBytes, 0, (struct sockaddr *)&readAddr, read_addr_size);
  nBytes = recvfrom(readSocket, buffer, 512, 0, NULL, NULL);
  if(nBytes < 0){
    printf("Unable to read file from the file_read service\n"); 
  }
  else{
    printf("Received %d bytes of data from the file_read service\n", nBytes);
    buffer[nBytes] = '\0';
  }
  return nBytes;
}

void scanViruses(char buffer[], char* result, char* arg, int filesize){
  printf("Scanning for viruses....\n");
  int scanSocket, nBytes, offset = 0;
  struct sockaddr_in scanAddr = connectToService(4444, &scanSocket);
  socklen_t scan_addr_size = sizeof scanAddr;
  nBytes = sendto(scanSocket, buffer, filesize, 0, (struct sockaddr *)&scanAddr, scan_addr_size);
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
      offset = sprintf(result+offset, "%s - infected\n", arg);
    }
    else
      offset = sprintf(result+offset, "%s - clean\n", arg);
  }
  return;
}

int main(int argc, char **argv){
  int udpSocket;
  char buffer[512];
  char result[1024];
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
  int ok = bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
  if(ok != 0){
    printf("Error in binding to the port 1111: %s\n", strerror(errno));
  }

  /*Initialize size variable to be used later on*/
  addr_size = sizeof serverStorage;

  int i;
  for(i = 1; i < argc; i++){
    // Get the update service to update the database
    getDatabaseUpdated(buffer);

    // Send filename to the file read service
    int filesize = readFile(buffer, argv[i]);

    // Scan the file contents for viruses
    scanViruses(buffer, result, argv[i], filesize);
    
  }
  printf("%s", result);
  return 0;
}
