from scapy.all import sniff, IP, ICMP, Raw

# IP address to bind to (loopback IP)
bind_ip = "127.0.0.1"

# Loopback interface (typically 'lo')
interface = "lo"

# Create a file to store the received data
with open('received_file.txt', 'wb') as f:
    def packet_callback(packet):
        # Check if the packet is ICMP and has the correct destination IP
        if packet.haslayer(ICMP) and packet[IP].dst == bind_ip:  # ICMP Echo Request
            payload = bytes(packet[Raw].load)  # Extract payload
            f.write(payload)  # Write payload to file
            f.flush()

    # Sniff ICMP packets on the loopback interface and filter by the destination IP
    sniff(filter=f"icmp and dst host {bind_ip}", prn=packet_callback, iface=interface, store=0)
