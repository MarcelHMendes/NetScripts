#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

int main(int argc, char *argv[]){
    struct hostent *host_info;
    struct in_addr *address;
    struct sockaddr_in ip_info;
    char name[NI_MAXHOST];

    memset(&ip_info, 0, sizeof(ip_info));
    ip_info.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &ip_info.sin_addr);
    
    if(argc < 2){
        printf("Usage: %s <hostname|ip> <-r:optional>\n", argv[0]);    
        exit(1);
    }
    if((argc == 3) && !(strcmp("-r", argv[2]))){
        int res = getnameinfo(( struct sockaddr *) & ip_info, sizeof(ip_info),
                                name, sizeof(name), NULL, 0, 0);
        if(res){
            printf("error: %d\n", res);
            exit(1);
        }else{
            printf("%s has name %s\n", argv[1], name);
        }
        return 0;
    }

    host_info = gethostbyname(argv[1]);
    if (host_info == NULL){
        printf("Couldn't lookup %s\n", argv[1]);    
    }else{
        address = (struct in_addr *) (host_info->h_addr);
        printf("%s has address %s\n", argv[1], inet_ntoa(*address));
    }

return 0;
}
