import time
from scapy.all import AsyncSniffer, IP, TCP, UDP
import pandas as pd
import joblib
from colorama import init, Fore, Style  # استيراد colorama للألوان

# تهيئة colorama
init()

# تحميل النموذج المدرب
model = joblib.load('PKL/svm_octa_icmp_pod_model.pkl')

# دالة لتحويل الـ IP إلى 4 أجزاء منفصلة
def ip_to_parts(ip):
    return list(map(int, ip.split('.')))

# دالة لمعالجة الحزم
def process_packet(packet):
    try:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            protocol = packet[IP].proto
            length = len(packet)
            ttl = packet[IP].ttl
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

            src_port, dst_port = None, None
            if TCP in packet or UDP in packet:
                src_port = packet.sport
                dst_port = packet.dport

            protocol_name = get_protocol_name(protocol)
            packet_data = [src, dst, protocol, length, ttl, timestamp, src_port, dst_port]

            # إذا كانت الحزمة ICMP، قم بالتنبؤ
            if protocol_name == "ICMP":
                # تحويل البيانات إلى تنسيق يتوافق مع النموذج
                processed_data = preprocess_packet(packet_data)
                result = model.predict(pd.DataFrame([processed_data], columns=model.feature_names_in_))
                status = "Attack Detected!" if result == 1 else "Normal"
                color = Fore.RED if result == 1 else Fore.GREEN  # أحمر للهجوم، أخضر للعادي
            else:
                status = "Normal (Non-ICMP)"
                color = Fore.GREEN  # أخضر للحزم العادية غير ICMP

            reset_color = Style.RESET_ALL  # إعادة تعيين اللون

            # عرض النتائج مع ترتيب واضح للمرسل والمستقبل
            print(f"{color}Source IP: {src}, Destination IP: {dst}, Protocol: {protocol_name}, Status: {status}{reset_color}")
    except Exception as e:
        print(f"Error processing packet: {e}")

# دالة للحصول على اسم البروتوكول
def get_protocol_name(proto):
    protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return protocols.get(proto, "Unknown")

# دالة لمعالجة البيانات قبل إرسالها للنموذج
def preprocess_packet(packet_data):
    # تحويل البيانات إلى تنسيق يتوافق مع النموذج
    src_parts = ip_to_parts(packet_data[0])  # تحويل IP المصدر إلى 4 أجزاء
    dst_parts = ip_to_parts(packet_data[1])  # تحويل IP الوجهة إلى 4 أجزاء

    processed_data = [
        0,  # Time
        packet_data[2],  # Protocol
        packet_data[3],  # Length
        0,  # ICMP Type 
        0,  # ICMP Code
        0,  # Traffic Rate
        0,  # Packet Interval
        src_parts[0],  # Source_1
        src_parts[1],  # Source_2
        src_parts[2],  # Source_3
        src_parts[3],  # Source_4
        dst_parts[0],  # Destination_1
        dst_parts[1],  # Destination_2
        dst_parts[2],  # Destination_3
        dst_parts[3],  # Destination_4
    ]
    return processed_data

# بدء التقاط الحزم
def start_sniffing():
    print("Starting packet capture...")
    sniffer = AsyncSniffer(prn=process_packet, store=False)  # لا تخزن الحزم في الذاكرة
    sniffer.start()
    return sniffer

if __name__ == '__main__':
    try:
        sniffer = start_sniffing()
        while True:
            time.sleep(1)  # إبقاء البرنامج يعمل
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        sniffer.stop()