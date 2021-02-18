#include <stdio.h>
#include <sys/socket.h>
#include <string.h>

int send_string(int sockfd, unsigned char *buffer){
    int sent_bytes, bytes_to_send;
    bytes_to_send = strlen((const char *) buffer);
    while(bytes_to_send > 0){
        sent_bytes = send(sockfd, buffer, bytes_to_send, 0);
        if(sent_bytes == -1)
            return 0;
        bytes_to_send -= sent_bytes;
        buffer += sent_bytes;
    }
    return 1; //Return 1 on sucess
}

int recv_line(int sockfd, unsigned char *dest_buffer){
    #define EOL "\r\n" //
    #define EOL_SIZE 2
    unsigned char *ptr;
    int eol_matched = 0;

    ptr = dest_buffer;
    while(recv(sockfd, ptr, 1, 0) == 1){
        if(*ptr == EOL[eol_matched]){
            eol_matched++;
            if(eol_matched == EOL_SIZE){
                *(ptr+1-EOL_SIZE) = '\0';
                return strlen((const char *) dest_buffer);
            }
        }else{
            eol_matched = 0;
        }
        ptr++;
    }
    return 0; //Didn't find EOL    
}

//Dumps raw memory in hex byte and printable split format
void dump(const unsigned char *data_buffer, const unsigned int length){
    unsigned char byte;
    unsigned int i, j;
    for(i=0; i < length; i++){
        byte = data_buffer[i];
        printf("%02x ", data_buffer[i]);
        if((i%16 == 15) || ((i == length-1))){
            for(j=0; j < 15-(i%16); j++)
                printf("  ");
            printf("| ");
            for(j=(i-(i%16)); j<= i ;j++){
                byte = data_buffer[j];
                if((byte > 31) && (byte < 127))
                    printf("%c", byte);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}

void pcap_fatal(const char *failed_in, const char *errbuf){
    printf("Fatal Error in %s: %s\n", failed_in, errbuf);
}
