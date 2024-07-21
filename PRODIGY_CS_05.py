import scapy.all as scapy

def packet_callback(packet):             #analysis captured packets, printing ip details and attempying to decode payload for TCP and UDP
                                        #scapy packet object containing network traffic info
    
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        # Handle TCP and UDP protocols with proper error handling
        if packet.haslayer(scapy.TCP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', errors='ignore')  # Handle decoding errors 
                print(f"TCP payload ")
            except (IndexError, UnicodeDecodeError):
                print("Unable to decode TCP payload.")

        elif packet.haslayer(scapy.UDP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', errors='ignore')  # Handle decoding errors 
                print(f"UDP payload ")  # Constrain UDP payload output
            except (IndexError, UnicodeDecodeError):
                print("Unable to decode UDP payload.")

def start_sniffing():
    """Starts capturing packets and processes them using the packet_callback function."""
    scapy.sniff(store=False, prn=packet_callback)

# Start sniffing packets
start_sniffing()


