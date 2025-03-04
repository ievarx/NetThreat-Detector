from scapy.all import *
import pandas as pd
import time
import csv

packets_data = []

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        packet_info = {
            'Time': packet.time,
            'Source': packet[IP].src,
            'Destination': packet[IP].dst,
            'Protocol': packet[IP].proto,
            'Length': len(packet),
            'ICMP Type': packet.getlayer(ICMP).type,  
            'ICMP Code': packet.getlayer(ICMP).code, 
            'Traffic Rate': 0,  
            'Packet Interval': 0,  # قيمة افتراضية
        }
        
        packets_data.append(packet_info)
        print(f"Packet captured: {packet_info}") 
        
        if len(packets_data) >= 100: 
            df = pd.DataFrame(packets_data)
            df.to_csv('captured_packets.csv', mode='a', header=not pd.io.common.file_exists('captured_packets.csv'), index=False)
            packets_data.clear()  #
            print("100 packets saved to CSV.")  #


def start_sniffing():
    print("Starting packet capture... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":

    with open('captured_packets.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            'Time', 'Source', 'Destination', 'Protocol', 'Length', 'ICMP Type', 'ICMP Code', 'Traffic Rate', 'Packet Interval'
        ])
    start_sniffing()