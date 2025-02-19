#!/usr/bin/python3

from scapy.all import *
import argparse

def packetcallback(packet):
  try:
    # The following is an example of Scapy detecting HTTP traffic
    # Please remove this case in your actual lab implementation so it doesn't pollute the alerts
    if packet[TCP].dport == 80:
      print("HTTP (web) traffic detected!")
  except Exception as e:
    # Uncomment the below and comment out `pass` for debugging, find error(s)
    #print(e)
    pass

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