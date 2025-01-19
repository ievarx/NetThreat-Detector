import sys
import time
import sqlite3
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, 
                             QTableWidget, QTableWidgetItem, QComboBox, 
                             QLineEdit, QStatusBar)
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
        except Exception as e:
            print(f"Error in detection: {str(e)}")

    def get_protocol_name(self, proto):
        protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return protocols.get(proto, "Unknown")

    def stop_sniffing(self):
        self.is_sniffing = False
        self.sniffer.stop()


class App(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.packet_data = []
        self.init_db()

    def initUI(self):
        self.setWindowTitle('Network Threat Detection Tool')
        layout = QVBoxLayout()

        # Network interface selection
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(['WiFi'])
        layout.addWidget(self.interface_combo)

        # Filter input
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText('Filter by Source IP...')
        layout.addWidget(self.filter_input)

        # Start capture button
        self.capture_button = QPushButton('Start Capture')
        self.capture_button.clicked.connect(self.start_capture)
        layout.addWidget(self.capture_button)

        # Stop capture button
        self.stop_capture_button = QPushButton('Stop Capture')
        self.stop_capture_button.clicked.connect(self.stop_capture)
        layout.addWidget(self.stop_capture_button)

        # Table to display packets
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(8)
        self.packet_table.setHorizontalHeaderLabels(['Source IP', 'Destination IP', 
                                                     'Protocol', 'Length', 'TTL', 
                                                     'Timestamp', 'Source Port', 'Dest Port'])
        layout.addWidget(self.packet_table)

        # Status bar
        self.status_bar = QStatusBar()
        layout.addWidget(self.status_bar)

        # Layout setup
        self.setLayout(layout)
        self.resize(800, 600)

    def init_db(self):
        self.conn = sqlite3.connect('packets.db')  # Fixed database file
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS packets (
                               source_ip TEXT, 
                               destination_ip TEXT, 
                               protocol TEXT, 
                               length INTEGER, 
                               ttl INTEGER, 
                               timestamp TEXT, 
                               source_port INTEGER, 
                               dest_port INTEGER)''')
        self.conn.commit()

    def start_capture(self):
        interface = self.interface_combo.currentText()
        self.sniffer_thread = PacketSnifferThread(interface)
        self.sniffer_thread.packet_signal.connect(self.add_packet)
        self.sniffer_thread.start()

    def add_packet(self, packet_data):
        self.packet_data.append(packet_data)
        self.update_table()

    def update_table(self):
        self.packet_table.setRowCount(0)
        for row_data in self.packet_data:
            row_position = self.packet_table.rowCount()
            self.packet_table.insertRow(row_position)
            for col_idx, item in enumerate(row_data):
                self.packet_table.setItem(row_position, col_idx, QTableWidgetItem(str(item)))

    def stop_capture(self):
        self.sniffer_thread.stop_sniffing()


if __name__ == '__main__':
    app_instance = QApplication(sys.argv)  # غيرنا الاسم علمود نتجنب التعارض
    window = App()
    window.show()
    sys.exit(app_instance.exec_())
