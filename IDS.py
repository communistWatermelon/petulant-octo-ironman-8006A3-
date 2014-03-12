"""
petulant-octo-ironman-8006A3-
=============================
A simple Python IDS for use on a Linux System

read userConfig.ini
    attemptLimit = number of attempts
    blockTLimit  = time limit for blocking each ip
    services     = dict of services to implement, and their bad password string

check logs
    read blockedIP.ini
        if currentTime - blockedDate > blockTLimit
            unblock the IP
    for each service
        find bad passwords from timeLastChecked until currentTime
        add each IP to a dictionary, increment every time
        if number > attemptLimit
            block the ip
            set the time for when it was blocked in blockedIP.ini
        
   write timeLastChecked to blockedIp.ini
   
files
    userConfig.ini  - the user configured variables
    blockedIP.ini   - list of blocked IPs and the time they were blocked, + time last checked
"""
import subprocess
import time
import os
import fileinput

attemptLimit = 5 
blockTLimit = 24
services = {}
fversion = 1

def main():
    services = readConfig()
    checkLogs()

def readConfig():
    with open("userConfig.ini") as f:
        for line in f:
            if line.startswith("#"):
                continue
            checkLine(line)
    return services 

def checkLine(line):
    global attemptLimit
    global blockTLimit
    global services
    global fversion

    line = stripWhitspace(line)

    if line.startswith("attemptLimit"):
        temp = line.split("=")
        attemptLimit = (temp[1])
    elif line.startswith("blockTLimit"):
        temp = line.split("=")
        blockTLimit = (temp[1])
    elif line.startswith("_"):
        temp = line.split("_")
        temp = temp[1].split(":")
        services[temp[0]] = temp[1]
    elif line.startswith("fversion"):
        temp = line.split("=")
        fversion = int(temp[1])
    return

def stripWhitspace(text):
    temp = text.rstrip()
    temp = temp.lstrip()
    return temp

def checkBlockedUsers():
    blockedUsers = {}
    lines = []
    with open("blockedIP.ini") as f:
        for line in f:
            temp = line.split(":")
            if time.time() - float(temp[0]) > (float(blockTLimit) * 3600):
                unBlockUser(temp[1])
            else:
                lines.append(line)

    with open("blockedIP.ini", "w") as f:
        for line in lines:
            f.write(line)
        
    return

def blockUser(user):
    print "Blocking " + user
    f = open("blockedIP.ini", "a")
    f.write(str(time.time()) + ":" + user + "\n")
    f.close()
    os.system("iptables -A INPUT -s " + str(user) + " -j DROP")
    return

def unBlockUser(user):
    print "Unblocking " + user
    for line in fileinput.input("blockedIP.ini", inplace=True):
        if not user in line:
            print(line),
    os.system("iptables -D INPUT -s " + str(user) + " -j DROP")
    return

def checkLogs():
    for service in services:
        if fversion == 20:
            command = "journalctl _COMM=" + service + " --no-pager --no-tail"
            searchLogs(subprocess.check_output(command, shell=True), service)
        else:
            command = "grep " + service + " /var/log/secure"
            searchLogs(subprocess.check_output(command, shell=True), service)

    return

def searchLogs(output, service):
    attempts = {}

    lines = output.split("\n")
    for line in lines:
        if services[service] in line:
            params = line.split(" ")
            attempts[params[10]] = attempts.get(params[10], 0) + 1
    decideBlock(attempts)

def decideBlock(attempts):
    for key in attempts:
        if int(attempts[key]) >= int(attemptLimit):
            blockUser(str(key))

main()