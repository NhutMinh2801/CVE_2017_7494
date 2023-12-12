import struct
import pyshark
import csv
import time
import tkinter as tk
from tkinter import ttk
import psutil
import threading
import asyncio
import binascii
import scapy.all as scapy
import logging
import os
import smbclient
import subprocess
import re
import dpkt
import smb
from scapy.all import *

packet_count_lock = threading.Lock()
packet_count = 0
max_packets = 1000
time_window = 60

# Function to capture packets
def capture_packets(selected_interface):
    loop = asyncio.new_event_loop()  # Create a new event loop for the thread
    asyncio.set_event_loop(loop)  # Set the event loop for the current thread
    try:
        with open(output_csv_file, mode='w', newline='') as csv_file:
            fieldnames = ['Timestamp', 'SourceIP', 'DestinationIP', 'Protocol', 'PacketLength', 'InfoPacket', 'Signature']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            capture = pyshark.LiveCapture(interface=selected_interface, eventloop=loop)
            for packet in capture.sniff_continuously():
                with packet_count_lock:
                    if packet_count >= max_packets or not capture_active:
                        window.after(1, lambda: info_label.config(text=f"Captured packets. Capture stopped."))
                        break
                    handle_packet(packet, writer)
    except KeyboardInterrupt:
        window.after(1, lambda: info_label.config(text="Capture stopped by the user"))
    finally:
        loop.close()

# Function to get a list of available network interfaces
def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return [iface for iface in interfaces]

# Global variable to track if the capture is active
capture_active = False
capture = None
output_csv_file = "output.csv"
writer = None

# Function to start packet capture
def start_capture():
    global capture_active, capture, writer
    if not capture_active:
        selected_interface = network_interface_combobox.get()
        output_csv_file = "output.csv"
        info_label.config(text="Capture in progress...")
        capture_thread = threading.Thread(target=capture_packets, args=(selected_interface,))
        capture_thread.start()
        capture_active = True

# Function to stop packet capture
def stop_capture():
    global capture_active, capture, writer
    if capture_active:
        capture_active = False
        if capture is not None:
            capture.close()  # Close the packet capture
        if writer is not None:
            writer.writerow({'Timestamp': "Capture stopped", 'SourceIP': "", 'DestinationIP': "", 'Protocol': "", 'PacketLength': "", 'InfoPacket': "", 'Signature': ""})
        info_label.config(text="Capture stopped.")
        
        # Close the CSV file properly
        if writer is not None:
            writer.writerfile.close()

# Function to handle each captured packet
def handle_packet(packet, writer):
    try:
        timestamp = packet.sniff_time
        source_ip = packet.ip.src
        destination_ip = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport if packet.transport_layer else ""
        protocol = packet.frame_info.protocols  # This will include all protocols
        result1 = protocol.split(":")[-1]
        source_port = packet[packet.transport_layer].srcport if packet.transport_layer else ""
        packet_length = len(packet)
        info_packet = f"{source_ip}:{source_port} -> {destination_ip}:{destination_port} {result1} Length={packet_length}"
        signature=create_signature(packet)
        writer.writerow({'Timestamp': timestamp, 'SourceIP': source_ip, 'DestinationIP': destination_ip, 'Protocol': result1, 'PacketLength': packet_length, 'InfoPacket': info_packet, 'Signature': signature})
        #print(packet.show())
    except AttributeError:
        pass

def check_negotiate_protocol_request(packet):
  """Kiểm tra xem layer SMB trong gói packet có chứa thông điệp Negotiate Protocol Request không.
  Args:
    packet: Gói packet.
  Returns:
    True nếu layer SMB trong gói packet chứa thông điệp Negotiate Protocol Request, False nếu không.
  """
  if packet[0:4] != b'SMB':
    return False
  header_length = struct.unpack('<I', packet[4:8])[0]
  if header_length < 12:
    return False
  if packet[8:12] != struct.pack('<H', 0x0000):
    return False
  return True

# Tạo cái signature để lưu vào file csv
def create_signature(packet):
    source_ip = packet.ip.src
    destination_ip = packet.ip.dst
    protocol = packet.frame_info.protocols
    result1 = protocol.split(":")[-1]
    packet_length = len(packet)

    if packet_length >= 100 and "smb" or "smb2" in result1 and check_negotiate_protocol_request(packet):
        print("Attack")
        signature = f"{source_ip}_{destination_ip}/{result1}/Detect"
    else:
        # Create a signature for non-detect
        print("No Attack")
        signature = f"{source_ip}_{destination_ip}/{result1}/Non-Detect"
    return signature

# Create the GUI window
window = tk.Tk()
window.title("Packet Capture and Detection")

# Create a combobox for network interface selection
network_interfaces = get_network_interfaces()
max_interface_width = max(len(iface) for iface in network_interfaces)
network_interface_combobox = ttk.Combobox(window, values=network_interfaces, width=max_interface_width)
network_interface_combobox.pack()

# Create a start button to initiate packet capture
start_button = tk.Button(window, text="Start Capture", command=start_capture)
start_button.pack()

# Create a stop button to stop packet capture
stop_button = tk.Button(window, text="Stop Capture", command=stop_capture)
stop_button.pack()

# Create an info label to display capture status
info_label = tk.Label(window, text="Ready to capture packets.")
info_label.pack()

# Run the GUI main loop
window.mainloop()
