#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <seccomp.h>
#include <fcntl.h>


uid_t privEscalate(char buffer[]){
  struct stat info;
  stat(buffer, &info);

  // I have added getuid() so to make the program look more general
  // Since we know owner is root, getuid would return 0
  uid_t real = getuid();
  uid_t file_owner = info.st_uid;
  if (setuid(file_owner) < 0){
    printf("error in setting euid: %s\n", strerror(errno));
  }
  else{
    printf("EUID set to %d\n", file_owner);
  }  
  return real;
}

int readFile(char buffer[]){
  uid_t real = privEscalate(buffer);
  FILE* fp;
  fp = fopen(buffer, "r");
  fseek(fp, 0, SEEK_END);
  long fpsize = ftell(fp);
  fseek(fp, 0, SEEK_SET);  //same as rewind(f);

  fgets(buffer, fpsize, fp);
  fclose(fp);

  setuid(real);
  printf("EUID set back to %d\n", real);
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
    exit(0);
  }

  /*Initialize size variable to be used later on*/
  addr_size = sizeof serverStorage;

  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);

  // Creating a whitelist
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 1, SCMP_A0(SCMP_CMP_EQ, udpSocket));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 1, SCMP_A0(SCMP_CMP_EQ, udpSocket));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1));

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_EQ, O_RDONLY));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setuid), 0);

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);

  seccomp_load(ctx);
  while(1){

    // Waits to hear from main service
    nBytes = recvfrom(udpSocket, buffer, 512, 0, (struct sockaddr *)&serverStorage, &addr_size);
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
  seccomp_release(ctx);

  return 0;
}
