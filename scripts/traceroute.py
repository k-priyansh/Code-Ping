import scapy.all as scapy

def traceroute_target(ip):
    try:
        result, _ = scapy.traceroute(ip, verbose=False)
        hops = [(hop[1].src, hop[1].time) for hop in result]
        return hops
    except Exception as e:
        return f"Error performing traceroute: {e}"
    
    
    
if __name__ == "__main__":
    target_ip = "google.com"
    hops = traceroute_target(target_ip)
    print("Traceroute result:")
    for hop in hops:
        print(f"Hop: {hop[0]}, Time: {hop[1]}")