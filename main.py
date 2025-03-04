import os
import time
import joblib
import pandas as pd
from collections import defaultdict
from scapy.all import AsyncSniffer, IP, TCP, UDP
from colorama import init, Fore, Style

init(autoreset=True)

def display_banner():
    os.system("clear" if os.name == "posix" else "cls")
    banner = f"""
{Fore.LIGHTBLACK_EX}{'-' * 72}
-{Fore.RED}{'#' * 70}-
-{Fore.RED}-# {' ' * 66}#-
-{Fore.RED}-# {'Optimized AI Model for DDoS Attacks Detection':^66}#-
-{Fore.RED}-# {' ' * 66}#-
-{Fore.RED}{'#' * 31}[v1.0.1]{'#' * 31}-
{Fore.LIGHTBLACK_EX}{'-' * 72}
"""
    print(banner)


def ip_to_parts(ip):
    return list(map(int, ip.split('.')))

def get_protocol_name(proto):
    protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return protocols.get(proto, "Unknown")

def preprocess_packet(packet_data):
    src_parts = ip_to_parts(packet_data[0])  
    dst_parts = ip_to_parts(packet_data[1]) 
    return [
        0, packet_data[2], packet_data[3], 0, 0, 0, 0,
        *src_parts, *dst_parts
    ]

attack_counter_live = defaultdict(int)

def process_packet(packet):
    try:
        if IP in packet:
            src, dst, proto, length, ttl = packet[IP].src, packet[IP].dst, packet[IP].proto, len(packet), packet[IP].ttl
            src_port, dst_port = (packet.sport, packet.dport) if TCP in packet or UDP in packet else (None, None)
            protocol_name = get_protocol_name(proto)
            
            if protocol_name == "ICMP":
                processed_data = preprocess_packet([src, dst, proto, length, ttl, time.time(), src_port, dst_port])
                result = model.predict(pd.DataFrame([processed_data], columns=model.feature_names_in_))
                status, color = ("Attack Detected!", Fore.RED) if result == 1 else ("Normal", Fore.GREEN)
                
                if result == 1:
                    attack_counter_live[src] += 1
            else:
                status, color = "Normal (Non-ICMP)", Fore.GREEN
            
            print(f"{color}Source: {src}, Destination: {dst}, Protocol: {protocol_name}, Status: {status}{Style.RESET_ALL}")
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing():
    print("Starting packet capture...")
    sniffer = AsyncSniffer(prn=process_packet, store=False)
    sniffer.start()
    return sniffer

def analyze_csv(file):
    data = pd.read_csv(file)
    data[['Source_1', 'Source_2', 'Source_3', 'Source_4']] = pd.DataFrame(data['Source'].apply(ip_to_parts).to_list(), index=data.index)
    data[['Destination_1', 'Destination_2', 'Destination_3', 'Destination_4']] = pd.DataFrame(data['Destination'].apply(ip_to_parts).to_list(), index=data.index)
    
    features = ["Time", "Protocol", "Length", "ICMP Type", "ICMP Code", "Traffic Rate", "Packet Interval", "Source_1", "Source_2", "Source_3", "Source_4", "Destination_1", "Destination_2", "Destination_3", "Destination_4"]
    predictions = model.predict(data[features])
    
    attack_counter = defaultdict(int)
    for i, ip in enumerate(data['Source']):  
        if predictions[i] == 1:
            attack_counter[ip] += 1
    
    for ip, count in attack_counter.items():
        if count > 100:
            print(Fore.RED+f"IP {ip} is considered an attacker with {count} attacks.")

if __name__ == "__main__":
    display_banner()
    model = joblib.load('PKL/svm_octa_icmp_pod_model.pkl')
    
    choice = input(Fore.LIGHTBLACK_EX + "\n[1] CSV-file Analyzer\n[2] Live Traffic Detection\n\nEnter your choice: ")
    
    if choice == "1":
        file_path = input("Enter the CSV file path: ")
        analyze_csv(file_path)
    elif choice == "2":
        try:
            sniffer = start_sniffing()
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping packet capture...")
            sniffer.stop()
            print("\nAttack Summary:")
            for ip, count in attack_counter_live.items():
                if count > 0:
                    print(Fore.RED + f"IP {ip} detected with {count} attack(s).")
    else:
        print(Fore.RED + "Invalid choice!")
