from scapy.all import *
from colorama import *
import time
import threading

# Banner and color setup
banner = '''

░█▀▄▀█ ▀█▀ ▀▀█▀▀ ░█▀▄▀█ 　 ░█▀▀▄ ░█▀▀▀ ▀▀█▀▀ ░█▀▀▀ ░█▀▀█ ▀▀█▀▀ ░█▀▀▀█ ░█▀▀█ 
░█░█░█ ░█─ ─░█── ░█░█░█ 　 ░█─░█ ░█▀▀▀ ─░█── ░█▀▀▀ ░█─── ─░█── ░█──░█ ░█▄▄▀ 
░█──░█ ▄█▄ ─░█── ░█──░█ 　 ░█▄▄▀ ░█▄▄▄ ─░█── ░█▄▄▄ ░█▄▄█ ─░█── ░█▄▄▄█ ░█─░█
===========================================================================
          Developed By AIZAZ-ART
'''
yellow = Fore.LIGHTYELLOW_EX
red = Fore.RED
Reset = Fore.RESET

print(f"{yellow}{banner}{Reset}")

# Function to get the MAC address for a given IP
def get_mac(ip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    ans, _ = srp(pkt, timeout=2, verbose=0)
    if ans:
        return ans[0][1].src
    return None

# Function to detect ARP spoofing
def detector(packet):
    if ARP in packet and packet[ARP].op == 2:  # ARP response (is-at)
        real_mac = get_mac(packet[ARP].psrc)  # Get the real MAC address
        response_mac = packet[ARP].hwsrc

        if real_mac and real_mac != response_mac:
            print(f"{red}[+] You Are Under ATTACK :( Real MAC: {real_mac} Fake MAC: {response_mac} {Reset}")
        
# Periodically scan the network to update the known IP-MAC mappings
def network_scan():
    global ip_mac_mapping
    ip_mac_mapping.clear()
    print(Back.LIGHTGREEN_EX+ Fore.BLACK + "Scanning network for devices..." + Style.RESET_ALL)
    arp_request = ARP(pdst="192.168.100.0/24")  # Adjust the IP range according to your network
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    for sent, received in answered_list:
        ip_mac_mapping[received.psrc] = received.hwsrc

# Continuously scan the network at intervals
def continuous_scan(interval):
    while True:
        network_scan()
        time.sleep(interval)

if __name__ == "__main__":
    ip_mac_mapping = {}  # Dictionary to store IP-MAC mappings

    # Initial network scan
    network_scan()
    
    # Start continuous scanning in a separate thread
    scan_thread = threading.Thread(target=continuous_scan, args=(60,))  # Scan every 60 seconds
    scan_thread.daemon = True
    scan_thread.start()
    
    # Start sniffing for ARP packets
    print("Starting ARP monitoring...")
    sniff(prn=detector, filter="arp", store=0)