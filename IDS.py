#!/usr/bin/python
"""
/*---------------------------------------------------------------------------------------
--  SOURCE FILE:    IDS.py - The python IDS
--
--  PROGRAM:        IDS
--
--  FUNCTIONS:      main()
--                  readConfig()
--                  checkLine(line)
--                  stripWhitspace(text)
--                  checkBlockedUsers()
--                  blockUser(user)
--                  unblockUser(user)
--                  checkLogs()
--                  searchLogs(output, service)
--                  decideBlock(attempts)
--
--  DATE:           March 12, 2014
--
--  DESIGNERS:      Jacob Miner
--
--  PROGRAMMERS:    Jacob Miner
--
--  NOTES:
--  A simple Python IDS for use on a Linux System
--  
---------------------------------------------------------------------------------------*/
"""
import subprocess
import time
import os
import fileinput

attemptLimit = 5 
blockTLimit = 24
services = {}
fversion = 1
blockedDir = "/home/jake/git/petulant-octo-ironman-8006A3-/"
configDir = "/home/jake/git/petulant-octo-ironman-8006A3-/"

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   main
--
--  DATE:       March 12, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: main()
--
--  RETURNS:  void
--
--  NOTES:  The main function of the program. Reads the config file, checks the logs, and 
--              unblocks users that have been blocked longer than the user-defined time limit.
--  
------------------------------------------------------------------------------*/
"""
def main():
    services = readConfig()
    checkLogs()
    checkBlockedUsers()


"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   readConfig
--
--  DATE:       March 12, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: readConfig()
--
--  RETURNS:  services - a list of user-defined services to check
--
--  NOTES:  Reads the config file, passing each parsable line to checkLine.
--  
------------------------------------------------------------------------------*/
"""
def readConfig():
    with open(configDir + "userConfig.ini") as f:
        for line in f:
            if line.startswith("#"):
                continue
            checkLine(line)
    return services 

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   checkLine
--
--  DATE:       March 12, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: checkLine(line)
--                          line - the line to match to a variable
--
--  RETURNS:  void
--
--  NOTES:  Used for setting the program variables. 
--  
------------------------------------------------------------------------------*/
"""
def checkLine(line):
    global attemptLimit
    global blockTLimit
    global services
    global fversion
    global blockedDir
    global configDir

    line = stripWhitspace(line)

    if line.startswith("attemptLimit"):
        temp = line.split("=")
        attemptLimit = (temp[1])
    elif line.startswith("blockTLimit"):
        temp = line.split("=")
        blockTLimit = (temp[1])
    elif line.startswith("configDir"):
        temp = line.split("=")
        configDir = (temp[1]) 
    elif line.startswith("blockedDir"):
        temp = line.split("=")
        blockedDir = (temp[1])
    elif line.startswith("_"):
        temp = line.split("_")
        temp = temp[1].split(":")
        services[temp[0]] = temp[1]
    elif line.startswith("fversion"):
        temp = line.split("=")
        fversion = int(temp[1])
    return

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   stripWhitspace
--
--  DATE:       March 12, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: stripWhitspace(text)
--                              text - the string to strip the whitespace from
--
--  RETURNS:  temp - the string without any whitespace.
--
--  NOTES:  Strips whitespace from text, on both sides of the string
--  
------------------------------------------------------------------------------*/
"""
def stripWhitspace(text):
    temp = text.rstrip()
    temp = temp.lstrip()
    return temp

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   checkBlockedUsers
--
--  DATE:       March 12, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: checkBlockedUsers()
--
--  RETURNS:  void
--
--  NOTES:  Reads blockedUser.ini, and determines if they are past the user-defined block length
--              if so, they are unblocked. 
------------------------------------------------------------------------------*/
"""
def checkBlockedUsers():
    lines = []
    with open(blockedDir+"blockedIP.ini") as f:
        for line in f:
            line = stripWhitspace(line)
            temp = line.split(":")
            if time.time() - float(temp[0]) > (float(blockTLimit) * 3600):
                unblockUser(temp[1])
            else:
                lines.append(line)

    with open(blockedDir+"blockedIP.ini", "w") as f:
        for line in lines:
            f.write(line)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   blockUser
--
--  DATE:       March 12, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: blockUser(user)
--                 user - the user to block
--
--  RETURNS:  void
--
--  NOTES:  Blocks the user using the firewall, and adds them to the blockedIP.ini file
------------------------------------------------------------------------------*/
"""
def blockUser(user):
    if user in open(blockedDir+'blockedIP.ini').read():
        return
    else: 
        print "Blocking " + user
        f = open(blockedDir+"blockedIP.ini", "a")
        f.write(str(time.time()) + ":" + user + "\n")
        f.close()
        os.system("iptables -A INPUT -s " + str(user) + " -j DROP")

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   unblockUser
--
--  DATE:       March 12, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: unBlockUser(user)
--                          user - the user to unblock
--
--  RETURNS:  void
--
--  NOTES:  Unblocks the user from the firewall, and removes them from the blockedIP.ini file
------------------------------------------------------------------------------*/
"""
def unblockUser(user):
    if user == "127.0.0.1":
        user = "localhost.localdomain"

    print "Unblocking " + user
    os.system("iptables -D INPUT -s " + str(user) + " -j DROP")
    for line in fileinput.input(blockedDir+"blockedIP.ini", inplace=True):
        if not user in line:
            print(line),

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   checkLogs
--
--  DATE:       March 12, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: checkLogs()
--
--  RETURNS:  void
--
--  NOTES:  Goes through all the user defined services, and reads the logs, then passes
--              the output to searchLogs. Fedora 20 uses a different method than other
--              iterations of fedora, do the version is checked.
------------------------------------------------------------------------------*/
"""
def checkLogs():
    for service in services:
        if fversion == 20:
            command = "journalctl _COMM=" + service + " --no-pager --no-tail"
            searchLogs(subprocess.check_output(command, shell=True), service)
        else:
            command = "grep " + service + " /var/log/secure"
            searchLogs(subprocess.check_output(command, shell=True), service)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   searchLogs
--
--  DATE:       March 12, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: searchLogs(output, service)
--                  output  - the full output of the logs 
--                  service - the service to search for
--
--  RETURNS:  void
--
--  NOTES:  Searches the log files [output] for each service, using their
--              user-defined "bad password" string. Checks each IP, and records 
--              the number of attempts, then decides if they should be blocked.
------------------------------------------------------------------------------*/
"""
def searchLogs(output, service):
    attempts = {}

    lines = output.split("\n")
    for line in lines:
        if services[service] in line:
            params = line.split(" ")
            attempts[params[10]] = attempts.get(params[10], 0) + 1
    decideBlock(attempts)

"""
/*------------------------------------------------------------------------------
--
--  FUNCTION:   decideBlock
--
--  DATE:       March 12, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: decideBlock(attempts)
--                      attempts - a list of ips, and the number of times they attempted to access a service
--
--  RETURNS:  void
--
--  NOTES:  Reads through a list of attempts, checking if the ip address 
--              passed the limit of allowed attempts. Blocks users who have too  
--              many attempts.
------------------------------------------------------------------------------*/
"""
def decideBlock(attempts):
    for key in attempts:
        if int(attempts[key]) >= int(attemptLimit):
            blockUser(str(key))

main()