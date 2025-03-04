import pandas as pd
import random

network_devices = [
    "192.168.2.50", "192.168.3.30", "192.168.0.130", "192.168.3.40",
    "192.168.2.55", "192.168.1.160", "192.168.0.70", "192.168.2.80"
]

attacker_ips = [
    "192.168.1.160", "192.168.3.30" ]

victim_ip = "192.168.1.120"

data = []
num_packets = 500000  
previous_time = 0    

for i in range(num_packets):
    time = round(previous_time + random.uniform(0.001, 1.0), 6)
    previous_time = time
    
    rand_choice = random.random()
    
    if rand_choice < 0.5:
        source = random.choice(network_devices)
        destination = random.choice(network_devices)
        length = random.randint(10, 50)          
        traffic_rate = random.uniform(1, 20)       
        packet_interval = round(random.uniform(0.05, 1.0), 6)  
        is_attack = 0
        protocol = 1                             
        icmp_type = random.choice([8, 0])          
        icmp_code = 0
        
    else:
        
        source = random.choice(attacker_ips)     
        destination = victim_ip                    
        length = random.randint(51, 1550)          
        traffic_rate = random.uniform(80, 150)     
        packet_interval = round(random.uniform(0.001, 0.01), 6)  
        is_attack = 1
        protocol = 1                             
        icmp_type = 8                            
        icmp_code = 0

    payload = f"<{'X' * random.randint(10, 100)}>"
    
    data.append([time, source, destination, protocol, length, icmp_type, icmp_code, payload, traffic_rate, packet_interval, is_attack])
    
columns = ["Time", "Source", "Destination", "Protocol", "Length", "ICMP Type", "ICMP Code", "Payload", "Traffic Rate", "Packet Interval", "Is_Attack"]
df = pd.DataFrame(data, columns=columns)

print(df.head(10))

df.to_csv("icmp_pod_data.csv", index=False)
print("Data generated successfully!")
