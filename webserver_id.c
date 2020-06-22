#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "network.h"

void fields_id(unsigned char * buffer){
    char *fields_array[13] = {"Server:", "Host:", "Origin:", "User-Agent:", "Allow:", "Content-Encoding:",
    "Content-MD5:", "Link:", "Location:", "Set-Cookie:", "Transfer-Encoding:","X-Frame-Options:",
    "X-XSS-Protection"};

    for(int i; i < 13;i++){
        if(strncasecmp((const char *) buffer, fields_array[i], (int) sizeof(fields_array[i])) == 0)
            printf("%s\n", buffer);
    }
}

int main(int argc, char *argv[]){
    int sockfd;
    struct hostent *host_info;
    struct sockaddr_in target_addr;
    unsigned char buffer[8096];
    unsigned char request[1000];

    if(argc < 2){
        printf("Usage: %s <hostname>\n", argv[0]);
        exit(1);
    }

    if((host_info = gethostbyname(argv[1])) == NULL){
        perror("looking up hostname");
        exit(1);
    }

    if((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1){
        perror("in socket");
        exit(1);
    }
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(80);
    target_addr.sin_addr = *((struct in_addr *) host_info->h_addr);
    memset(&(target_addr.sin_zero), '\0', 8);

    if(connect(sockfd, (struct sockaddr *) &target_addr, sizeof(struct sockaddr)) == -1){
        perror("connection to server");
        exit(1);
    }

    char *request_array[2] = {"OPTIONS", "HEAD"};
    for(int i = 0; i < 2; i++){
        strcpy((char *) request, request_array[i]);
        strcat((char *) request, " / HTTP/1.1\r\n\r\n");

        send_string(sockfd, (unsigned char *) request);

        while(recv_line(sockfd, buffer)){
            fields_id(buffer);
            memset(buffer, '\0', 8096);
        }
    }
    return 0;
}
