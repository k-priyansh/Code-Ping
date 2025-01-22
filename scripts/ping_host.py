import scapy.all as scapy


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
    
if __name__ == "__main__":
    localip= "192.168.29.9" #link
    result = ping_host(localip)
    print(result)