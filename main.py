from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        payload = packet.payload

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")

        if TCP in packet:
            print("Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print("Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        print(f"Payload: {payload.payload}")
        print("-" * 40)

def start_sniffing(interface):
    print(f"Starting packet sniffing on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)

def main():
    print("Packet Sniffer Tool")
    interface = input("Enter the network interface to sniff on (e.g., eth0, wlan0): ")
    start_sniffing(interface)

if __name__ == "__main__":
    main()
