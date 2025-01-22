import socket


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


if __name__ == "__main__":
    router_ip="192.168.29.1"
    check_router_vulnerabilities(router_ip)
