import sys
import time
import sqlite3
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, 
                             QTableWidget, QTableWidgetItem, QComboBox, 
                             QLineEdit, QStatusBar, QDialog, QLabel, QGridLayout, QFileDialog)
from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import AsyncSniffer, IP, TCP, UDP

# Thread for packet sniffing
class PacketSnifferThread(QThread):
    packet_signal = pyqtSignal(list)  # Signal to send packet data to the UI

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.sniffer = None
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
            packet_data = [src, dst, protocol_name, length, ttl, timestamp, src_port, dst_port]
            self.packet_signal.emit(packet_data)

    def get_protocol_name(self, proto):
        protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return protocols.get(proto, "Unknown")

    def stop_sniffing(self):
        self.is_sniffing = False
        self.sniffer.stop()

# Main app window
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
        self.packet_table.cellClicked.connect(self.show_packet_details)
        layout.addWidget(self.packet_table)

        # Status bar
        self.status_bar = QStatusBar()
        layout.addWidget(self.status_bar)

        # Save to database button
        self.save_db_button = QPushButton('Save to Database')
        self.save_db_button.clicked.connect(self.save_to_database)
        layout.addWidget(self.save_db_button)

        # Show data button
        self.show_db_button = QPushButton('Show Data')
        self.show_db_button.clicked.connect(self.show_data)
        layout.addWidget(self.show_db_button)

        # Layout setup
        self.setLayout(layout)
        self.resize(800, 600)

        # Filter change event
        self.filter_input.textChanged.connect(self.update_table)

    def init_db(self):
        # Initialize the database with a fixed name
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
        # Add packet to table and database
        self.packet_data.append(packet_data)
        self.update_table()

        self.cursor.execute('''INSERT INTO packets 
                               (source_ip, destination_ip, protocol, length, ttl, timestamp, source_port, dest_port) 
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', packet_data)
        self.conn.commit()

    def update_table(self):
        # Update table with packet data and filter applied
        self.packet_table.setRowCount(0)
        filter_text = self.filter_input.text()

        for row_data in self.packet_data:
            if filter_text in row_data[0]:  # Filter by source IP
                row_position = self.packet_table.rowCount()
                self.packet_table.insertRow(row_position)
                for col_idx, item in enumerate(row_data):
                    self.packet_table.setItem(row_position, col_idx, QTableWidgetItem(str(item)))

    def show_packet_details(self, row, column):
        packet_data = self.packet_data[row]
        details_dialog = QDialog(self)
        details_dialog.setWindowTitle("Packet Details")

        layout = QGridLayout()
        labels = ['Source IP', 'Destination IP', 'Protocol', 'Length', 'TTL', 
                  'Timestamp', 'Source Port', 'Destination Port']
        
        for i, label in enumerate(labels):
            layout.addWidget(QLabel(label), i, 0)
            layout.addWidget(QLabel(str(packet_data[i])), i, 1)
        
        details_dialog.setLayout(layout)
        details_dialog.exec_()

    def save_to_database(self):
        # Save the current data to the fixed database
        self.conn.commit()

    def show_data(self):
        self.cursor.execute("SELECT * FROM packets")
        data = self.cursor.fetchall()

        # Show data in a popup
        show_data_dialog = QDialog(self)
        layout = QVBoxLayout()
        for row in data:
            layout.addWidget(QLabel(str(row)))
        show_data_dialog.setLayout(layout)
        show_data_dialog.exec_()

    def stop_capture(self):
        # Stop the packet sniffer
        self.sniffer_thread.stop_sniffing()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec_())
