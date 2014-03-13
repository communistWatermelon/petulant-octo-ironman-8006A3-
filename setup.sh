# A simple setup script, to make the IDS run every minute. 
#!/bin/bash
echo "* * * * * root $(dirname $(readlink -f $0))/IDS.py" >> /etc/crontab