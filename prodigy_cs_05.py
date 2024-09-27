from scapy.all import sniff

# Callback function to process captured packets
def packet_callback(packet):
    print(packet.show())  # Shows all packet details

# Sniff packets on the default network interface
sniff(prn=packet_callback, count=10)  # Capture 10 packets
#Extracting relevant information.
from scapy.all import IP, sniff

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet.proto
        payload = bytes(packet[IP].payload)
        
        print(f"Source: {ip_src} | Destination: {ip_dst} | Protocol: {protocol} | Payload: {payload}")

sniff(prn=packet_callback, count=10)
