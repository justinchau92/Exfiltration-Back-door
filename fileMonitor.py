#!/usr/bin/env python
##  =================================================================
#  	SOURCE FILE: fileMonitor.py
#  
#
#	DATE: Dec 4th 2017
#  
#  
#  	AUTHOR: Paul Cabanez, Justin Chau
#
#	
#	DESCRIPTION: FileMonitor class that is used for watching file events
#	
#
#	LAST REVISED: October 19th 2017
#  =================================================================

import watchdog, time, encryption, configReader, helpers
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileMonitor(FileSystemEventHandler):
	clientIP = ""
	def __init__(self,clientIP):
		self.clientIP = clientIP
		self.masterkey = encryption.MASTER_KEY
		
	def on_created(self,event):	
		try:
			#helpers.sendFile(self.clientIP, event.src_path, 6000)
			
			helpers.fileSender(self.clientIP, event.src_path, 6000)
			print "File Created: " + event.src_path
			print "Calling send file\n"
		except IOError as e:
			#print "I/O error({0}): {1}".format(e.errno, e.strerror)
			if e.errno == 2:
				print "File was created but does not exist anymore, possible temp file\n"
			if e.errno == 21:
				print "Folder " + event.src_path + " has been created\n"
				helpers.sendMessage("Folder " + event.src_path + " has been created\n", configReader.srcIP, 9000)
		
	def on_deleted(self,event):
		print "File deleted: " + event.src_path + "\n"
		helpers.sendMessage("File deleted: " + event.src_path, configReader.srcIP, 9000)
		
	def on_moved(self,event):
		print "File Modified: " + event.dest_path
		print "Calling send file\n"
		helpers.sendFile(self.clientIP, event.dest_path, 6000)
		
	#def on_modified(self,event):
	#	
	#	try:
	#		helpers.sendFile(self.clientIP, event.src_path, 6000)
	#		print "File/Folder has been modified: " + event.src_path
	#		print "Sending copy of file"
	#	except IOError as e:
	#		print "I/O error({0}): {1}".format(e.errno, e.strerror)
