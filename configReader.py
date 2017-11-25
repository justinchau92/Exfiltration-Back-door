#!/usr/bin/env python
#  =================================================================
#  	SOURCE FILE: configReader.py
#  
#
#	DATE: Dec 4th 2017
#  
#  
#  	AUTHOR: Paul Cabanez, Justin Chau
#
#	
#	DESCRIPTION: Reads config.txt file and places settings into variables
#	
#
#	LAST REVISED: Nov 22nd 2017
#  =================================================================

import ConfigParser
configParser = ConfigParser.RawConfigParser()
configPath = r'config.txt'
configParser.read(configPath)

##read config file and settings
password = configParser.get('config','password')
directory = configParser.get('config', 'fileDir')
srcIP = configParser.get('config', 'srcIP')
destIP = configParser.get('config', 'destIP')
destPort = configParser.get('config', 'destPort')
protocol = configParser.get('config', 'protocol')
portknock = configParser.get('config', 'portknocks')
portknockArray = portknock.split(',')
