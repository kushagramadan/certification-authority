#!/usr/bin/python

import socket
import sys
import time
import hashlib
from Crypto.PublicKey import RSA
from Crypto import Random
from time import gmtime, strftime

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host = socket.gethostname()
port = int(sys.argv[1])
s.bind((host, port))

state = 0
client_id = 0
msg = ""
f = open('./server_keys/server_key.pem', 'rb')
server_bin_priv_key = f.read()
server_priv_key_obj = RSA.importKey(server_bin_priv_key)


s.listen(5)
while True:
   	c, addr = s.accept()
   	data =  c.recv(1024)
   	if (state == 0):
	   	client_id = data.decode('utf-8')
	   	state = 1
	   	print("Step:1")
	elif (state == 2):
		print("Step:2")
		emsg = data
		msg = server_priv_key_obj.decrypt(emsg)
 		pub_f = open('./server_keys/key' + client_id + '.pub', 'rb')
 		actual_pub_key = pub_f.read()
 		actual_hash = hashlib.sha512(client_id + "_" + str(actual_pub_key)).hexdigest()
 		if(msg == actual_hash):
 			#identity and public key verified
 			tos = strftime("%Y-%m-%d %H:%M:%S", gmtime())
 			actual_hash = hashlib.sha512(client_id + "_" + str(actual_pub_key) + "_" + tos).digest()
 			sign = server_priv_key_obj.sign(actual_hash, '')
 			c.send(tos + "_" + str(sign))
 		state = 0
 		client_id = 0

	if(state == 1):
		state = 2
	c.close()

