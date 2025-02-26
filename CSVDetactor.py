#هذا البرنامج يستخدم الذكاء الاصطناعي بالتحليل لكن  الحزم تكون بصيغة ملف   csv 

import pandas as pd
from collections import defaultdict
import joblib

# دالة لتقسيم الـ IP إلى أوكتات
def ip_to_parts(ip):
    return list(map(int, ip.split('.')))

# 1. قراءة ملف CSV
data = pd.read_csv('Data/captured_packets.csv')

# 2. تقسيم عناوين الـ IP إلى أوكتات
data[['Source_1', 'Source_2', 'Source_3', 'Source_4']] = pd.DataFrame(data['Source'].apply(ip_to_parts).to_list(), index=data.index)
data[['Destination_1', 'Destination_2', 'Destination_3', 'Destination_4']] = pd.DataFrame(data['Destination'].apply(ip_to_parts).to_list(), index=data.index)

# 3. تحميل النموذج
model = joblib.load('PKL/svm_octa_icmp_pod_model.pkl')

# 4. اختيار الميزات (Features)
features = [
    "Time", "Protocol", "Length", "ICMP Type", "ICMP Code", "Traffic Rate", "Packet Interval",
    "Source_1", "Source_2", "Source_3", "Source_4",
    "Destination_1", "Destination_2", "Destination_3", "Destination_4"
]

# 5. إعداد البيانات للتنبؤ
X = data[features]

# 6. التنبؤ
predictions = model.predict(X)

# 7. عد الهجمات
attack_counter = defaultdict(int)
attacker_details = []

for i, ip in enumerate(data['Source']):
    if predictions[i] == 1:  # افترض أن 1 يعني هجوم
        attack_counter[ip] += 1
        if attack_counter[ip] > 50:
            attacker_details.append(ip)

# 8. إخراج النتائج
for ip in set(attacker_details):
    print(f"IP {ip} is considered an attacker with {attack_counter[ip]} attacks.")
