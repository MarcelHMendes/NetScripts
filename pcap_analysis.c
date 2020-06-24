#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "network.h"
#include "layers.h"
#include <arpa/inet.h>

#define PACKETS 32

void pcap_fatal(const char *, const char *);
void decode_ethernet(const u_char *);
void decode_ip(const u_char *);
//u_int decode_tcp(const u_char *);
void caught_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc, char *argv[]){
    char choice;
    int num_dev, max_packets;
    //struct pcap_pkthdr header;
    //const u_char *packet;
    const char errbuf[PCAP_ERRBUF_SIZE];
    char *device;
    pcap_t *pcap_handle;
    pcap_if_t *interfaces, *temp;
    int i = 0;

    if(argc > 2){
        printf("Usage: ./pcap_analysis <num_packets: optional>\n");
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
    
    pcap_loop(pcap_handle, max_packets, caught_packet, NULL);
    pcap_close(pcap_handle);

    return 0;    
}

void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet){
    int tcp_header_length, total_header_size, pkt_data_len;
    u_char *pkt_data;

    printf("====Got a %d byte packet ====\n", cap_header->len);

    decode_ethernet(packet);
    decode_ip(packet+ETHER_HDR_LEN);
    //tcp_header_length = decode_tcp(packet+ETHER_HDR_LEN+sizeof(struct ip_hdr));

    total_header_size = ETHER_HDR_LEN+sizeof(struct ip_hdr);//+tcp_header_length;
    pkt_data = (u_char *) packet + total_header_size;
    pkt_data_len = cap_header->len - total_header_size;
    if(pkt_data_len > 0){
        printf("\n\t\t\t%u bytes of packet data\n", pkt_data_len);
        dump(pkt_data, pkt_data_len);
    } else {
        printf("\t\tNo Packet Data");    
    }
}

void decode_ethernet(const u_char *header_start){
    const struct ether_hdr *ethernet_header;

    ethernet_header = (const struct ether_hdr *) header_start;
    printf("[[Layer 2 :: Ethernet Header ]]\n");
    printf("[Source %02x", ethernet_header->ether_src_addr[0]);
    for(int i = 1; i < ETHER_ADDR_LEN; i++)
        printf(":%02x", ethernet_header->ether_src_addr[i]);
    printf("\tDest: %02x", ethernet_header->ether_dest_addr[0]);
    for(int i = 0; i < ETHER_ADDR_LEN;i++){
        printf(":%02x", ethernet_header->ether_dest_addr[i]);
    }
    printf("\tType: %hu]\n", ethernet_header->ether_type);
}

void decode_ip(const u_char *header_start){
    const struct ip_hdr *ip_header;

    ip_header = (const struct ip_hdr *) header_start;
    printf("\n(( Layer 3 ::: IP Header ))\n");
    printf("(Source: %s\t", (char *) inet_ntoa( ip_header->ip_src_addr));
    printf("Dest: %s)\n", (char *) inet_ntoa(ip_header->ip_dest_addr));
    printf("(Type: %u\t HDL: %d)\n", (u_int) ip_header->ip_type, (u_int8_t) ip_header->ip_hdr_len * 4);
    printf("(IP ID: %d\t Version: %d)", ip_header->ip_id, (u_int8_t) ip_header->ip_version);
}
