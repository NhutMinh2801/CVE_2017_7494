import tkinter as tk
from tkinter import ttk
import scapy.all as scapy
import csv
import re
import psutil
import time
import threading


# Global variable to track the sniffing state
sniffing = False
sniffer_thread = None

def start_sniffing():
    global sniffing, sniffer_thread
    if not sniffing:
        selected_interface = network_interface_combobox.get()
        output_file = "output.csv"
        sniffing = True

        # Create a new thread for sniffing
        sniffer_thread = threading.Thread(target=sniff_packets, args=(selected_interface, output_file))
        sniffer_thread.start()
        start_button.config(state="disabled")
        stop_button.config(state="active")
def stop_sniffing():
    global sniffing, sniffer_thread
    if sniffing:
        sniffing = False

        # Wait for the sniffer thread to finish
        sniffer_thread.join()

        start_button.config(state="active")
        stop_button.config(state="disabled")

def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return [iface for iface in interfaces]

def sniff_packets(interface, output_file):
    try:
        print(f"Sniffing packets on interface {interface}...")

        # Open the CSV file for writing
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['Timestamp', 'SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort', 'Protocol', 'PacketLength', 'InfoPacket', 'Signature']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()

            # Use the sniff function to capture packets on the specified interface
            scapy.sniff(iface=interface, store=False, prn=lambda x: process_packet(x, writer))

    except KeyboardInterrupt:
        print("Sniffing stopped.")


def process_packet(packet, writer):
    if packet.haslayer(scapy.IP):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        #protocol = packet[scapy.IP].proto
        protocol = packet.frame_info.protocols
        source_port = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else ""
        destination_port = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else ""
        packet_length = len(packet)
        info_packet = f"{source_ip}:{source_port} -> {destination_ip}:{destination_port} {protocol} Length={packet_length}"
        signature = create_signature(packet)

        writer.writerow({
            'Timestamp': timestamp,
            'SourceIP': source_ip,
            'DestinationIP': destination_ip,
            'SourcePort': source_port,
            'DestinationPort': destination_port,
            'Protocol': protocol,
            'PacketLength': packet_length,
            'InfoPacket': info_packet,
            'Signature': signature
        })
        #process_packet(packet)
        # Check for the specific HTTP GET request
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            if "\\172.16.1.135\test\\" in load:
                print("Detected:")
                print(load)
                # Log or take appropriate action here
        #print_packet_payload(packet)
        print_packet_payload(packet)
def create_signature(packet):
    source_ip = packet[scapy.IP].src
    destination_ip = packet[scapy.IP].dst
    #protocol = packet[scapy.IP].proto
    protocol = packet.frame_info.protocols
    packet_length = len(packet)
    # Check if the packet has a Raw layer
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')

        # Check if the info field contains the specified path
        if "\\172.16.1.135\test\\" in load or packet_length >= 100:
            info = "Path: \\172.16.1.135\test\\"
        else:
            info = "Other"

        # Create a signature including the source IP, destination IP, protocol, and info
        signature = f"{source_ip}_{destination_ip}/{protocol}/Detect"
    else:
        # Create a signature for non-HTTP packets
        signature = f"{source_ip}_{destination_ip}/{protocol}/Non-Detect"

    return signature

def print_packet_payload(packet):
    # Check if the packet has a Raw layer
    if packet.haslayer(scapy.Raw):
        # Decode the payload to a string using UTF-8 encoding
        payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')

        # Use a regular expression to check for the presence of .so file content
        so_file_pattern = re.compile(r'\.so\b')
        if so_file_pattern.search(payload):
            print("SO file content found in the payload:")
            print(payload)
        else:
            print("No .so file content found in the payload.")
    else:
        print("No Raw layer found in the packet.")

def start_sniffing():
    selected_interface = network_interface_combobox.get()
    output_file = "output.csv"
    sniff_packets(selected_interface, output_file)

# Create the GUI window
window = tk.Tk()
window.title("Packet Sniffer")

# Create a combobox for network interface selection
network_interfaces = get_network_interfaces()
max_interface_width = max(len(iface) for iface in network_interfaces)
network_interface_combobox = ttk.Combobox(window, values=network_interfaces, width=max_interface_width)
network_interface_combobox.pack()

# Create a start button to initiate packet capture
start_button = tk.Button(window, text="Start Sniffing", command=start_sniffing)
start_button.pack()

# Create a stop button to stop packet capture
stop_button = tk.Button(window, text="Stop Sniffing", command=stop_sniffing, state="disabled")
stop_button.pack()

# Run the GUI main loop
window.mainloop()
