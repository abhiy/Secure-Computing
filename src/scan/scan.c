#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <seccomp.h>
#include <fcntl.h>

void scanForViruses(char* file, char* threatfile, char* scan_result){
  int i, j, k;
  for(i = 3; i < strlen(file); i++){
    for(j = 3; j < strlen(threatfile); j+=3){
      if(file[i] == threatfile[j]){
        for(k = 0; k < 4; k++){
          if(file[i-k] != threatfile[j-k]){
            break;
          }
          else{
            if(k == 3){
              scan_result[0] = '1';
              return;
            }
          }
        }
      }
    }
  }
}

void scanFile(char* file , char* scan_result, FILE* fp){
  char threatfile[512];
  fseek(fp, 0, SEEK_END);
  long fpsize = ftell(fp);
  fseek(fp, 0, SEEK_SET);  //same as rewind(f);

  fgets(threatfile, fpsize, fp);

  scanForViruses(file, threatfile, scan_result);
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
  serverAddr.sin_port = htons(4444);
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

  /*Bind socket with address struct*/
  int ok = bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

  if(ok != 0){
    printf("Error in binding to the port 4444: %s\n", strerror(errno));
    exit(0);
  }

  /*Initialize size variable to be used later on*/
  addr_size = sizeof serverStorage;
  char scan_result[1];

  FILE* fp;
  fp = fopen("/home/aby/Sem-1/Security/hw-2/Project/db/threat", "r");
  int fd = fileno(fp);

  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);

  // Creating a whitelist
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 1, SCMP_A0(SCMP_CMP_EQ, udpSocket));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 1, SCMP_A0(SCMP_CMP_EQ, udpSocket));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1));

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, fd));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, 1));

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, fd));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 1, SCMP_A0(SCMP_CMP_EQ, fd));

  seccomp_load(ctx);
  while(1){
    scan_result[0] = '0';
    // Waits to hear from main service
    nBytes = recvfrom(udpSocket, buffer, 1024, 0, (struct sockaddr *)&serverStorage, &addr_size);
    if(nBytes < 0){
      printf("Unable to get the request from main service\n");
      continue;
    }
    else{
      buffer[nBytes] = '\0';
      printf("Received request to scan a file\n");
    }
    //scan_result[0]  = scanFile(buffer);
    scanFile(buffer, scan_result, fp);
    nBytes = sendto(udpSocket, scan_result, 1, 0, (struct sockaddr *)&serverStorage, addr_size);
    if(nBytes < 0){
      printf("Unable to send the scan results to the main service \n");
    }
    else{
      printf("Sent results to the main service\n");
    }
  }
  seccomp_release(ctx);

  fclose(fp);
  return 0;
}
