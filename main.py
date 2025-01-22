import scapy.all as scapy
import socket
import netifaces
#import struct
import requests 


# Function to get the IP range of the network
def get_ip_range():
    try:
        # Connect to an external server to determine the local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # Google DNS server
            local_ip = s.getsockname()[0]
        print(local_ip)
        # --- hostname = socket.gethostname()
        # --- print(hostname)
    except Exception as e:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        cidr = f"{local_ip}/24"
        # return cidr
        return f"Error: {e}"
    

# Function to perform ARP scan
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

# Function to scan ports
def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port  # Return the open port
    except:
        pass
    finally:
        sock.close()
    return None  # If no connection, return None

def get_service_name(port):
    try:
        # Get the service name for the port using socket
        return socket.getservbyport(port)
    except socket.error:
        # Return "Unknown Service" if port is not found
        return "Unknown Service"

def scan_ports(ip, port_range=(1, 9024)):
    import concurrent.futures
    open_ports = []
    # with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        # Create a list of tasks for the port scan
        tasks = [executor.submit(scan_port, ip, port) for port in range(port_range[0], port_range[1] + 1)]
        
        # Collect results as they are completed
        for future in concurrent.futures.as_completed(tasks):
            port = future.result()
            if port:
                open_ports.append(port)
                
        for port in open_ports:
            service = get_service_name(port)
            print(port,":", service)


# Router vulnerability check
def check_router_vulnerabilities(ip):
    common_ports = [21, 22, 23, 80, 443, 8080]
    vulnerabilities = []
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                vulnerabilities.append(f"Port {port} is open")
        except:
            pass
        finally:
            sock.close()
    for vuls in vulnerabilities: 
        print(vuls)

# Ping host
def ping_host(ip):
    try:
        response = scapy.sr1(scapy.IP(dst=ip)/scapy.ICMP(), timeout=1, verbose=False)
        if response:
            print(f"Host is ONLINE")
            # return f"{ip} is reachable."
        else:
            print(f"Host is OFFLINE")
            # return f"{ip} is not reachable."
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
        return f"Error pinging {ip}: {e}"

# Traceroute
def traceroute_target(ip):
    try:
        result, _ = scapy.traceroute(ip, verbose=False)
        hops = [(hop[1].src, hop[1].time) for hop in result]
        return hops
    except Exception as e:
        return f"Error performing traceroute: {e}"

# WiFi scanner
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

# Wake on LAN
def wake_on_lan(mac_address):
    # Remove colons or dashes and validate MAC address format
    mac_address = mac_address.replace(":", "").replace("-", "")
    if len(mac_address) != 12:
        return "Invalid MAC address format."
    magic_packet = bytes.fromhex("FF" * 6 + mac_address * 16)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Replace '255.255.255.255' with your network's broadcast address if needed
        sock.sendto(magic_packet, ('192.168.1.255', 9))  # Example broadcast address
        print("Magic Packet:",magic_packet)
        return f"Magic packet sent to {mac_address}."
    except Exception as e:
        return f"Error sending magic packet: {e}"
    finally:
        sock.close()

# Main program menu
def start():
    while True:
        print("\nFing Clone - Network Utility Tool")
        print("1. Scan Network")
        print("2. Scan Ports")
        print("3. Router Vulnerability Check")
        print("4. Ping Host")
        print("5. Traceroute")
        print("6. WiFi Scanner")
        print("7. Wake on LAN")
        print("8. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            ip_range = get_ip_range()
            scan_network()
        elif choice == "2":
            target_ip = input("Enter the target IP: ")
            ports = scan_ports(target_ip, port_range=(1, 1024))
        elif choice == "3":
            router_ip = input("Enter the router IP: ")
            vulnerabilities = check_router_vulnerabilities(router_ip)
            print(vulnerabilities)
        elif choice == "4":
            target_ip = input("Enter the target IP: ")
            result = ping_host(target_ip)
            print(result)
        elif choice == "5":
            target_ip = input("Enter the target IP: ")
            hops = traceroute_target(target_ip)
            print("Traceroute result:")
            for hop in hops:
                print(f"Hop: {hop[0]}, Time: {hop[1]}")
        elif choice == "6":
            interface = input("Enter the WiFi interface (e.g., wlan0): ")
            networks = wifi_scanner(interface)
            print("Available WiFi Networks:")
            for ssid, bssid in networks:
                print(f"SSID: {ssid}, BSSID: {bssid}")
        elif choice == "7":
            mac_address = input("Enter the MAC address: ") #70:97:41:E6:B1:F8
            # sudo ufw allow 9/udp
            # sudo iptables -A INPUT -p udp --dport 9 -j ACCEPT
            result = wake_on_lan(mac_address)
            print(result)
        elif choice == "8":
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    start()
