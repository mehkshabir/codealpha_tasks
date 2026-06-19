from scapy.all import sniff, IP, wrpcap, get_if_list

# Show available interfaces (run once to pick correct one)
print("Available interfaces:")
print(get_if_list())

# Set interface (you can leave None for auto)
INTERFACE = None   # or paste like: "\\Device\\NPF_{...}"

# Store packets for saving later
captured_packets = []

# Function to process each packet
def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet.proto

        print(f"{src} -> {dst}")

        # Save packet for PCAP file
        captured_packets.append(packet)

# Start sniffing
print("\nStarting packet capture...\n")

sniff(
    iface=INTERFACE,
    prn=process_packet,
    store=False,
    filter="ip"   # only IP traffic (clean output)
)

# Save captured packets to file
wrpcap("capture.pcap", captured_packets)

print("\nSaved to capture.pcap")