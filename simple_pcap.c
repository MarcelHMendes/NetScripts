#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "network.h"

#define PACKETS 32

//void pcap_fatal(const char *failed_in, const char *errbuf){
//    printf("Fatal error in %s: %s\n", failed_in, errbuf);
//    exit(1);
//}

int main(int argc, char *argv[]){
    char choice;
    int num_dev, max_packets;
    struct pcap_pkthdr header;
    const u_char *packet;
    const char errbuf[PCAP_ERRBUF_SIZE];
    char *device;
    pcap_t *pcap_handle;
    pcap_if_t *interfaces, *temp;
    int i = 0;

    if(argc > 2){
        printf("Usage: ./simple_pcap <num_packets: optional>\n");
        exit(1);
    }

    if(argv[1] != NULL)
        max_packets = atoi(argv[1]);
    else
        max_packets = PACKETS;

    device = pcap_lookupdev((char *) errbuf);
    if(pcap_findalldevs(&interfaces, (char *) errbuf) != -1){
        for(temp=interfaces;temp;temp=temp->next){
            printf("%d: %s\n",i++ , temp->name);
        }
    
        printf("Do you want to choose a specific device?(Y/N)\n");
        scanf("%c", &choice);
        
        if((choice == 'Y') || (choice == 'y')){
            i = 0;
            printf("Type the device number\n");
            scanf("%d", &num_dev);
            for(temp=interfaces;temp;temp=temp->next){
                if(i == num_dev){
                    device = temp->name;
                    break;
                }        
                i++;
            }
        }
    }
    
    if(device == NULL)
        pcap_fatal("pcap_lookupdev", errbuf);
    
    printf("Sniffing on device\n");
    
    pcap_handle = pcap_open_live(device, 4096, 1, 0, (char *) errbuf);
    if(pcap_handle ==NULL)
        pcap_fatal("pcap_open_live", errbuf);
    
    for(int i=0; i < max_packets;i++){
        packet = pcap_next(pcap_handle, &header);
        printf("Got a %d byte packet\n", header.len);
        dump(packet, header.len);
    }
    
    pcap_close(pcap_handle);

    return 0;    
}
