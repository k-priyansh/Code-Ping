import scapy.all as scapy
import socket


def scan_network():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))  # Google DNS server
        ip_range = s.getsockname()[0]
        subnet = "/24"
        target_ip = f"{ip_range}{subnet}"
    # print(ip_range)    
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Parse the responses
    devices = []
    for sent, received in answered_list:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    # Print discovered devices
    print("Available devices in the network:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")


if __name__ == "__main__":
    scan_network()
