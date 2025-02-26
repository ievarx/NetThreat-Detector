from scapy.all import *
import pandas as pd
import time
import csv

# تعريف قائمة لتخزين الحزم
packets_data = []

# دالة لاستخلاص خصائص الحزم
def packet_callback(packet):
    # التحقق من أن الحزمة تحتوي على ICMP
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        # استخراج الخصائص المطلوبة
        packet_info = {
            'Time': packet.time,
            'Source': packet[IP].src,
            'Destination': packet[IP].dst,
            'Protocol': packet[IP].proto,
            'Length': len(packet),
            'ICMP Type': packet.getlayer(ICMP).type,  # نوع ICMP
            'ICMP Code': packet.getlayer(ICMP).code,  # كود ICMP
            'Traffic Rate': 0,  # قيمة افتراضية
            'Packet Interval': 0,  # قيمة افتراضية
        }
        
        # إضافة الحزمة إلى القائمة
        packets_data.append(packet_info)
        print(f"Packet captured: {packet_info}")  # طباعة الحزمة التي تم التقاطها
        
        # تخزين الحزم في ملف CSV بعد كل عملية التقاط
        if len(packets_data) >= 100:  # بعد كل 100 حزمة، يتم تخزين البيانات
            df = pd.DataFrame(packets_data)
            df.to_csv('captured_packets.csv', mode='a', header=not pd.io.common.file_exists('captured_packets.csv'), index=False)
            packets_data.clear()  # إعادة تهيئة قائمة الحزم بعد التخزين
            print("100 packets saved to CSV.")  # طباعة تأكيد حفظ البيانات

# التقاط الحزم من الشبكة
def start_sniffing():
    print("Starting packet capture... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0)  # store=0 يعني عدم تخزين الحزم في الذاكرة

# بدء التقاط الحزم
if __name__ == "__main__":

    with open('captured_packets.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            'Time', 'Source', 'Destination', 'Protocol', 'Length', 'ICMP Type', 'ICMP Code', 'Traffic Rate', 'Packet Interval'
        ])
    start_sniffing()