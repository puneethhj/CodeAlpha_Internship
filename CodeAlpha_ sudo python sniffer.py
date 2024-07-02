from scapy.all import sniff, IP, TCP

# Define a callback function to process packets
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"New Packet: {ip_layer.src} -> {ip_layer.dst}")
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")

# Start sniffing
print("Starting sniffer...")
sniff(filter="ip", prn=packet_callback, count=10)
print("Sniffing finished.")
