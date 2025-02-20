#!/usr/bin/python3

from scapy.all import *
from scapy.layers import http
import argparse

incident_number = 0

def packetcallback(packet):
  global incident_number

  try:
    # Detect NULL scan 
    if packet[TCP].flags == "":
        incident_number += 1
        print(f"ALERT #{incident_number}: NULL scan is detected from {packet[IP].src} (TCP)!")
  
    # Detect FIN scan
    if packet[TCP].flags == "F":
        incident_number += 1
        print(f"ALERT #{incident_number}: FIN scan is detected from {packet[IP].src} (TCP)!")
    
    # Detect Xmas scan
    if packet[TCP].flags == "FPU":
        incident_number += 1
        print(f"ALERT #{incident_number}: Xmas scan is detected from {packet[IP].src} (TCP)!")
    
    # Detect usernames and passwords sent in-the-clear via HTTP Basic Authentication
    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
        req = packet.getlayer('HTTP Request')

        if req:
            auth = req.Authorization
        
            if auth and auth.startswith(b'Basic'):
              incident_number += 1
              username, password = base64_bytes(auth.split(None, 1)[1]).split(b':', 1)
              print(f"ALERT #{incident_number}: Usernames and passwords sent in-the-clear (HTTP) (username: {username.decode()}, password: {password.decode()})")

        # Detect Nikto scan 
        payload = packet[TCP].load.decode("ascii").strip()
        if "Nikto" in payload:
            incident_number += 1
            print(f"ALERT #{incident_number}: Nikto scan is detected from {packet[IP].src} (TCP)!")
                    
    # Detect usernames and passwords sent in-the-clear via IMAP
    if packet[TCP].dport == 143 or packet[TCP].sport == 143:
        
        payload = packet[TCP].load.decode("ascii").strip()
        if "LOGIN" in payload:
            payload_tokens = payload.split()
            username = payload_tokens[2]
            password = payload_tokens[3][1:-1]
            incident_number += 1
            print(f"ALERT #{incident_number}: Usernames and passwords sent in-the-clear (IMAP) (username: {username}, password: {password})")

    # Detect usernames and passwords sent in-the-clear via FTP
    if packet[TCP].dport == 21 or packet[TCP].sport == 21:
        
        payload = packet[TCP].load.decode("ascii").strip()
        global ftp_username
        global ftp_password
        if "USER" in payload:
            ftp_username = payload.split("USER")[1].strip()
        if "PASS" in payload:
            ftp_password = payload.split("PASS")[1].strip()
        if ftp_username and ftp_password:
            incident_number += 1
            print(f"ALERT #{incident_number}: Usernames and passwords sent in-the-clear (FTP) (username: {ftp_username}, password: {ftp_password})")
            ftp_username, ftp_password = None, None

    # Detect SMB scan
    if packet[TCP].dport in [137, 138, 139, 445] or packet[TCP].sport in [137, 138, 139, 445]:
        incident_number += 1
        print(f"ALERT #{incident_number}: Scanning for SMB Protocol detected from {packet[IP].src} (TCP)!")

    # Detect Remote Desktop Protocol (RDP) 
    if packet[TCP].dport == 3389 or packet[TCP].sport == 3389:
        incident_number += 1
        print(f"ALERT #{incident_number}: Scanning for RDP scan is detected from {packet[IP].src} (TCP)!")
    
    # Detect VNC scan
    if packet[TCP].dport == 5900 or packet[TCP].sport == 5900:
        incident_number += 1
        print(f"ALERT #{incident_number}: Scanning for VNC instance detected from {packet[IP].src} (TCP)!")
        

  except Exception as e:
    # Uncomment the below and comment out `pass` for debugging, find error(s)
    print(e)
    #pass

# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")