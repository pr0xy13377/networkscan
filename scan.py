from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
target_ip = "192.168.0.1/24" 
arp = ARP(pdst=target_ip)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp

result = srp(packet, timeout=3, verbose=0)[0]

clients = []

for sent, received in result:
    ip = received.psrc
    icmp = IP(dst=ip)/ICMP()
    response = sr1(icmp,verbose=0)
    ttl = response[0].ttl
    print(ttl)
    if ttl == 64:
        os = "Linux (Kernel 2.4 and 2.6) or Google Linux or FreeBSD"
    elif ttl == 128:
        os = "Windows Vista and 7 (Server 2008) or Windows XP"
    elif ttl == 255:
        os = "iOS 12.4 (Cisco Routers)"
    else:
        os = "Unknown"
    # for each response, append ip and mac address to `clients` list
    clients.append({'ip': received.psrc, 'mac': received.hwsrc, 'os': os})

# print clients
print("Available devices in the network:")
print("IP" + " "*18+"MAC"+" "*18+"OS")
for client in clients:
    print("{:16}    {}    {} ".format(client['ip'], client['mac'],client['os']))
