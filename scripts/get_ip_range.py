import scapy.all as scapy
import socket
import netifaces

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
        return local_ip
    except Exception as e:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        cidr = f"{local_ip}/24"
        # return cidr
        return f"Error: {e}"