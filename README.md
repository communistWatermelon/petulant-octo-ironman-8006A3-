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