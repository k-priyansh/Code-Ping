import scapy.all as scapy
import socket

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
   
        
if __name__ == "__main__":
    mac_address = "70:97:41:E6:B1:F8" # Mac Address of mobile
    result = wake_on_lan(mac_address)
    # sudo ufw allow 9/udp
    # sudo iptables -A INPUT -p udp --dport 9 -j ACCEPT
    print(result)