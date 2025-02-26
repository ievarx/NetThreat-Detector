import pandas as pd
import random

# قائمة الأجهزة داخل الشبكة (للحركة الطبيعية)
network_devices = [
    "192.168.2.50", "192.168.3.30", "192.168.0.130", "192.168.3.40",
    "192.168.2.55", "192.168.1.160", "192.168.0.70", "192.168.2.80"
]

# قائمة أجهزة المهاجمين (  مجموعة فرعية من network_devices)
attacker_ips = [
    "192.168.1.160", "192.168.3.30" ]

# عنوان الضحية (Target)
victim_ip = "192.168.1.120"

data = []
num_packets = 500000  # عدد الحزم
previous_time = 0     # لتتبع الزمن 

for i in range(num_packets):
    # حساب الزمن (Time)
    time = round(previous_time + random.uniform(0.001, 1.0), 6)
    previous_time = time
    
    rand_choice = random.random()
    
    if rand_choice < 0.5:
        # حركة طبيعية (ICMP) - 50%
        source = random.choice(network_devices)
        destination = random.choice(network_devices)
        length = random.randint(10, 50)          # طول بين 10 و50 بايت
        traffic_rate = random.uniform(1, 20)       # معدل مرور طبيعي
        packet_interval = round(random.uniform(0.05, 1.0), 6)  # فاصل زمني طبيعي
        is_attack = 0
        protocol = 1                             # ICMP فقط
        icmp_type = random.choice([8, 0])          # Echo Request or Echo Reply
        icmp_code = 0
        
    else:
        # حركة هجومية (ICMP) - 50%
        source = random.choice(attacker_ips)     # المصدر من قائمة المهاجمين فقط
        destination = victim_ip                    # الوجهة هي الضحية فقط
        length = random.randint(51, 1550)          # طول بين 51 و1550 بايت
        traffic_rate = random.uniform(80, 150)     # معدل مرور مرتفع
        packet_interval = round(random.uniform(0.001, 0.01), 6)  # فاصل زمني قصير جدًا
        is_attack = 1
        protocol = 1                             # ICMP فقط
        icmp_type = 8                            # Echo Request فقط
        icmp_code = 0

    # الحمولة (Payload) عشوائية بطول 10-100 حرف من X
    payload = f"<{'X' * random.randint(10, 100)}>"
    
    data.append([time, source, destination, protocol, length, icmp_type, icmp_code, payload, traffic_rate, packet_interval, is_attack])
    
columns = ["Time", "Source", "Destination", "Protocol", "Length", "ICMP Type", "ICMP Code", "Payload", "Traffic Rate", "Packet Interval", "Is_Attack"]
df = pd.DataFrame(data, columns=columns)

# عرض أول 10 صفوف للتأكد من صحة البيانات
print(df.head(10))

# حفظ البيانات إلى ملف CSV
df.to_csv("icmp_pod_data.csv", index=False)
print("Data generated successfully!")
