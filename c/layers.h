#include <netinet/in.h>

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct ether_hdr{
    unsigned char ether_dest_addr[ETHER_ADDR_LEN];  //Destination MAC address
    unsigned char ether_src_addr[ETHER_ADDR_LEN];   //Source MAC address
    unsigned short ether_type;
};

struct ip_hdr{
    unsigned char ip_hdr_len:4, ip_version:4; //Version header length
    unsigned char ip_tos; //Type of service
    unsigned short ip_len; //Total length
    unsigned short ip_id; //Identification number
    unsigned short ip_frag_offset; //Fragment offset and flags
    unsigned char ip_ttl; //Time to live 
    unsigned char ip_type;  //protocol type
    unsigned short ip_checksum; 
    struct in_addr ip_src_addr; // Source IP 
    struct in_addr ip_dest_addr; // Destination IP 
};

struct tcp_hdr{
    unsigned short tcp_src_port;
    unsigned short tcp_dest_port;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    unsigned char reserved:4; // 4 bits from the 6 bits of reserved space
    unsigned char tcp_offset:4; //TCP data offset for little-endian host
    unsigned char tcp_flags; //TCP flags (and two bits of reserved space)
#define TCP_FYN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
    unsigned short tcp_window;
    unsigned short tcp_checksum;
    unsigned short tcp_urgent;    
};

struct udp_hdr{
    unsigned short udp_src_port;
    unsigned short udp_dest_port;
    unsigned short udp_len;
    unsigned short udp_sum;
};
