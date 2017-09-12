#!/usr/bin/python

import socket
import sys
import time
import hashlib
from Crypto.PublicKey import RSA
from Crypto import Random


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host = socket.gethostname()
port = int(sys.argv[1])
client_id = sys.argv[2]

while True:
	print("Client ID: " + client_id)
	print("Select an action:\n1) Get certificate from CA\n2) Send hello to a client\n3) Receive message from client")
	inp = input()
	if (int(inp) == 1):
		#Generate certificate
		server_port = port - int(client_id)
		s = socket.socket()
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.connect((host, server_port))
		f = open('./server_key.pub', 'rb')
		server_bin_pub_key = f.read()
		f = open('.//client' + client_id + '/key' + client_id + '.pub', 'rb')
		client_bin_pub_key = f.read()
		msg = client_id + '_' + str(client_bin_pub_key)
		server_pub_key_obj = RSA.importKey(server_bin_pub_key)
		msg_hash = hashlib.sha512(msg).hexdigest()
		emsg = server_pub_key_obj.encrypt(msg_hash, 'x')[0]
		s.sendall(client_id)
		s.close 
		time.sleep(3)
		s = socket.socket()
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.connect((host, server_port))
		s.sendall(emsg)
		data = s.recv(1024)
		data = data.decode('utf-8').split('_')

		with open("./client" + client_id + "/certificate" + client_id + ".txt", "wb") as cert_file:
			cert_file.write("Time of issuance: " + data[0] + "\n")
			cert_file.write("ID: " + client_id + "\n")
			cert_file.write("Key:\n")
			cert_file.write(str(client_bin_pub_key))
			cert_file.write("CA Signature: " + data[1] + "\n")
		s.close
		print("Certificate saved!\n")
	elif (int(inp) == 2):
		#Send hello
		recv_id = input("Enter Client ID: ")
		s = socket.socket()
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.connect((host, port - int(client_id) + int(recv_id)))
		s.sendall(client_id)
		recv_certificate = s.recv(2048)
		recv_certificate = recv_certificate.decode('utf-8').split('\n')
		l = len(recv_certificate)
		recv_time = recv_certificate[0]
		recv_time = recv_time.split(": ")
		recv_time = recv_time[1].replace("\n", "")
		recv_id = recv_certificate[1]
		recv_id = recv_id.split(": ")
		recv_id = recv_id[1]
		recv_pub_key = recv_certificate[3] + "\n"
		for i in range(4, l-2):
			recv_pub_key = recv_pub_key + recv_certificate[i] + "\n"
		recv_sig = recv_certificate[l-2]
		recv_sig = recv_sig.split(": ")
		recv_sig = recv_sig[1]
		pub_f = open('./server_key.pub', 'rb')
 		ca_pub_key = pub_f.read()
 		ca_pub_key_obj = RSA.importKey(ca_pub_key)
 		recv_hash = hashlib.sha512(recv_id + "_" + str(recv_pub_key) + "_" + recv_time).digest()
 		recv_sig = eval(recv_sig)
 		if(ca_pub_key_obj.verify(recv_hash, recv_sig)):
 			print("Certificate verified!")
 			s.close
			time.sleep(3)
			s = socket.socket()
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			s.connect((host, port - int(client_id) + int(recv_id)))
			msg = "hello from client " + client_id
			recv_pub_key_obj = RSA.importKey(recv_pub_key)
			emsg = recv_pub_key_obj.encrypt(msg, 'x')[0]
			s.sendall(emsg)
			s.close
			print("Sent message to client " + recv_id + "\n")
			time.sleep(1)
 		else:
 			print("Invalid certificate!\n")
 			s.close
 			time.sleep(1)


	elif (int(inp) == 3):
		#receive hello
		s.close
		s = socket.socket()
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((host, port))
		s.listen(5)
		c, addr = s.accept()
		recv_client_id = c.recv(1024)
		f = open("./client" + client_id + "/certificate" + client_id + ".txt" ,"rb")
		msg = f.read()
		c.send(msg)
		c.close()
		c, addr = s.accept()
		recv_emsg = c.recv(1024)
		f = open("./client" + client_id + "/key" + client_id + '.pem', 'rb')
		priv_key = f.read()
		priv_key_obj = RSA.importKey(priv_key)
		recv_msg = priv_key_obj.decrypt(recv_emsg)
		print("Message received from client " + recv_client_id + ": " + recv_msg + "\n")
		s.close

