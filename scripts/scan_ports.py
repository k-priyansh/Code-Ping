import scapy.all as scapy
import socket
import concurrent.futures

target_ip = "192.168.29.1"

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
        
    # print(f"Open ports on {ip}: {open_ports}")


if __name__ == "__main__":
    scan_ports(target_ip, port_range=(1, 9024))