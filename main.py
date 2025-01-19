import sys
import time
import sqlite3
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, 
                             QTableWidget, QTableWidgetItem, QComboBox, 
                             QLineEdit, QStatusBar, QDialog, QLabel, QGridLayout)
from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import AsyncSniffer, IP, TCP, UDP
from model import predict_attack  # استدعاء النموذج

class PacketSnifferThread(QThread):
    packet_signal = pyqtSignal(list)  # Signal to send packet data to the UI
    attack_signal = pyqtSignal(str)   # Signal to send attack alerts

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.sniffer = None
        self.packet_counts = {}
        self.is_sniffing = True

    def run(self):
        self.sniffer = AsyncSniffer(iface=self.interface, prn=self.process_packet)
        self.sniffer.start()

    def process_packet(self, packet):
        if not self.is_sniffing:
            return

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

            protocol_name = self.get_protocol_name(protocol)

            # إنشاء الميزات لتحليلها
            packet_features = [length, ttl, protocol]

            # تحليل الحزمة باستخدام النموذج
            self.detect_attack(src, packet_features)

            # تحديث الواجهة بالبيانات
            packet_data = [src, dst, protocol_name, length, ttl, timestamp, src_port, dst_port]
            self.packet_signal.emit(packet_data)

    def detect_attack(self, src_ip, packet_features):
        try:
            prediction = predict_attack(packet_features)
            if prediction == [1]:
                self.attack_signal.emit(f"Attack detected from {src_ip}")
            else:
                self.status_bar.showMessage(f"No attack detected for {src_ip}", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"Error in detection: {str(e)}", 5000)

    def get_protocol_name(self, proto):
        protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return protocols.get(proto, "Unknown")

    def stop_sniffing(self):
        self.is_sniffing = False
        self.sniffer.stop()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec_())
