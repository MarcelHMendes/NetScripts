# Description: Extracting Information from PCAP Files with Scapy

# Scapy is a powerful packet manipulation tool that can be used to extract information from PCAP files.
# In this example, we will read a PCAP file and extract information about the packets, such as Ethernet, IP, and TCP headers,
# as well as the payload (if available). We will also try to parse HTTP and HTTPS (TLS) traffic to extract additional information.
#
# To run this example, you will need to install Scapy using pip:
#
# pip install scapy
# You can then run the following code to extract information from a PCAP file:
#
# python pcap_extract.py
# Replace 'your_file.pcap' with the path to your PCAP file. The code will read the PCAP file, extract information from each packet, and print it to the console. It will also try to parse HTTP and HTTPS (TLS) traffic to extract additional information.
#
# Note: This example is for educational purposes only and should be used responsibly.

from scapy.all import rdpcap, Ether, IP, TCP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse  # For HTTP parsing
from datetime import datetime

def read_pcap(file_path):
    # Read the pcap file
    packets = rdpcap(file_path)

    for i, packet in enumerate(packets):
        print(f"Packet {i+1}:")
        timestamp = packet.time
        readable_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')

        print(f"(Timestamp: {readable_time}):")

        # Check if the packet has an Ethernet layer
        if Ether in packet:
            print(f"  Ethernet Source: {packet[Ether].src}")
            print(f"  Ethernet Destination: {packet[Ether].dst}")

        # Check if the packet has an IP layer
        if IP in packet:
            print(f"  IP Source: {packet[IP].src}")
            print(f"  IP Destination: {packet[IP].dst}")
            print(f"  IP Protocol: {packet[IP].proto}")
            print(f"  IP TTL: {packet[IP].ttl}")
            print(f"  IP Length: {packet[IP].len}")
            print(f"  IP Flags: {'DF' if packet[IP].flags.DF else ''} {'MF' if packet[IP].flags.MF else ''}")
            print(f"  IP Fragment Offset: {packet[IP].frag}")
        # Check if the packet has a TCP layer
        if TCP in packet:
            print(f"  TCP Source Port: {packet[TCP].sport}")
            print(f"  TCP Destination Port: {packet[TCP].dport}")
            print(f"  TCP Sequence Number: {packet[TCP].seq}")
            print(f"  TCP Acknowledgment Number: {packet[TCP].ack}")
            print(f"  TCP Window Size: {packet[TCP].window}")
            print(f"  TCP Flags: {get_tcp_flags(packet[TCP].flags)}")

            # Check if the packet has a Raw layer (payload)
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                payload = packet[Raw].load
                payload_size = len(payload)  # Tamanho do payload em bytes
                print(f"  Tamanho do Payload: {payload_size} bytes")
                #print(f"  Payload (Hex): {payload.hex()}")
                #print(f"  Payload (ASCII): {payload.decode('utf-8', errors='ignore')}")

                # Try to parse HTTP traffic
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:  # HTTP ports
                    try:
                        if b"HTTP" in payload:  # Check if it's HTTP traffic
                            if b"GET" in payload or b"POST" in payload:
                                print("  HTTP Request Detected:")
                                print(f"    Payload: {payload.decode('utf-8', errors='ignore')}")
                            elif b"HTTP/" in payload:
                                print("  HTTP Response Detected:")
                                print(f"    Payload: {payload.decode('utf-8', errors='ignore')}")
                    except Exception as e:
                        print(f"  Error parsing HTTP: {e}")

                # Try to parse HTTPS (TLS) traffic
                if packet[TCP].dport == 443 or packet[TCP].sport == 443:  # HTTPS ports
                    try:
                        if packet.haslayer(Raw):
                            payload = packet[Raw].load
                            print("\n[+] HTTPS (TLS) Traffic Detected")

                            payload = packet[Raw].load
                            payload_size = len(payload)  # Tamanho do payload em bytes
                            print(f"  Tamanho do Payload: {payload_size} bytes")
                            #print(f"  Payload (Hex): {payload.hex()}")
                            #print(f"  Payload (ASCII): {payload.decode('utf-8', errors='ignore')}")

                            if payload.startswith(b'\x16\x03'):  # TLS Handshake
                                print("    TLS Handshake Detected")
                                tls_version = payload[1:3]  # Posição da versão TLS
                                handshake_type = payload[5]  # Tipo de Handshake

                                # Mapear versões TLS conhecidas
                                tls_versions = {
                                    b'\x03\x01': "TLS 1.0",
                                    b'\x03\x02': "TLS 1.1",
                                    b'\x03\x03': "TLS 1.2",
                                    b'\x03\x04': "TLS 1.3"
                                }
                                version_str = tls_versions.get(tls_version, "Unknown Version")
                                print(f"    TLS Version: {version_str}")

                                # Identificar Handshake Type
                                if handshake_type == 1:  # Client Hello
                                    print("      Client Hello Detected")
                                    # Obter Cipher Suites suportadas (posição 43 no ClientHello)
                                    cipher_suites_length = int.from_bytes(payload[43:45], 'big')
                                    cipher_suites = payload[45:45 + cipher_suites_length]
                                    print(f"      Supported Cipher Suites: {cipher_suites.hex()}")
                                    # Procurar extensão SNI (Server Name Indication)
                                    extensions_start = 45 + cipher_suites_length + 2
                                    if b'\x00\x00' in payload[extensions_start:]:  # ID da extensão SNI é 0x0000
                                        print("      Server Name Indication (SNI) Present")
                                elif handshake_type == 2:  # Server Hello
                                    print("      Server Hello Detected")
                                    # Cipher Suite escolhido pelo servidor (posição 43 no ServerHello)
                                    chosen_cipher = payload[43:45]
                                    print(f"      Chosen Cipher Suite: {chosen_cipher.hex()}")
                    except Exception as e:
                        print(f"  Error parsing HTTPS (TLS): {e}")
        print("-" * 40)

def get_tcp_flags(flags):
    """Helper function to decode TCP flags."""
    flag_names = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR',
    }
    active_flags = [flag_names[flag] for flag in str(flags) if flag in flag_names]
    return ', '.join(active_flags)

if __name__ == "__main__":
    # Replace 'your_file.pcap' with the path to your PCAP file
    pcap_file = "capture.pcap" #'amp.TCP.reflection.SYNACK.pcap'
    read_pcap(pcap_file)
