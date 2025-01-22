import scapy.all as scapy

def wifi_scanner(interface="wlan0"):
    scapy.conf.iface = interface
    networks = set()

    def sniff_packet(packet):
        if packet.haslayer(scapy.Dot11Beacon):
            ssid = packet.info.decode() if packet.info else "Hidden SSID"
            bssid = packet.addr2
            print(f"Captured Packet: {packet.summary()}") # Print raw packet info
            print(f"Detected Network: SSID={ssid}, BSSID={bssid}")  # Debugging print
            networks.add((ssid, bssid))

    try:
        print("Scanning for WiFi networks...")  # Debugging print
        scapy.sniff(iface=interface, prn=sniff_packet, timeout=30, store=False)
    except Exception as e:
        return f"Error scanning WiFi: {e}"

    return list(networks)

if __name__ == "__main__":
    interface = "wlan0"  # Update this if necessary
    networks = wifi_scanner(interface)
    print("Available WiFi Networks:")
    for ssid, bssid in networks:
        print(f"SSID: {ssid}, BSSID: {bssid}")
