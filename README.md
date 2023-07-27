# CWAF_Syslog
This tool collects and sends security, bots and user events to an external syslog server

# ChangeLog

v4.3.1
- Collects DDoS events with --ddos argument

v4.2.1
- Added running the code with argument
		
- Added optional parameters
	- --waf used as a flag to collect waf security events
	- --bots used as a flag to collect bots events
	- --activity used as a flag to collect user activity

## Functionality to be added:

- Use of proxy which requires an authentication

# Overview 

The purpose of this script is to collect different types of events and send it to any syslog server :
1.	Syslog server listening on TCP port
2.	Syslog server listening on UDP port
3.  Syslog server listening on TCP port with TLS encryption

The script interacts with Radware Cloud WAF portal and collects all the necessary data through REST API calls.

IMPORTANT
● Read the entire file before attempting to configure/executing.


# Script Output

The script output if pre-formatted and each value is stored in a "key=value" format.

Depending on the event type, some keys may exist or not.

# Components for the script operation

## “CWAF_API_Syslog.py”

“CWAF_API_Syslog.py” is the only python file containing all the required functions. Below is the list of the variables that you need to pass as parameters : 

    --user: Your Cloud WAAP API user
    --password: Your Cloud WAAP API password
    --interval: Interval between logs collection
    --server: IP address of your syslog server
    --port: Listening port of your syslog server
    --transport: Transport protocol, either tcp or udp
    --cert: Certificate used with your syslog server
    --ssl: Activate SSL encryption with your syslog server
    --proxyAddress: IP address of outgoing proxy
    --proxyPort: Port of outgoing proxy
    --waf: Flag to collect waf security events
    --bots: Flag to collect bots events
    --activity: Flag to collect user activity logs
	--ddos: Flag to collect DDoS security events logs

Execution command should look like : python CWAF_API_Syslog.py --security --bots --activity --user <user> --password <password> --interval <interval_second> --server <syslog_server> --port <syslog_port> --transport <tcp/udp> [--cert <SSL_certificate>] [--ssl] [--proxyAddress <proxy-address> -proxyPort <proxy-port>]

# Setup

## Requirements

The solution requires python 3.6 and higher
The following packages are required but they are included as part of the standard 3.6 library- no need to install

sys
time
datetime
json
http.client
re
getopt
from logging.handlers import SysLogHandler
logging
socket
ssl
argparse

Packages in use – may require installation 

psutil
tls-syslog

Use the following command in order to install them

pip install -r requirements.txt

## Instructions and recommendations to run on the external server

1. Place the script folder into the appropriate location on the server
2. Install dependencies and necessary libraries/packages
3. You don't need to run it periodically, as with interval parameter it will automatically be done
4. Navigate to the folder containing the script and run 
python3 CWAF_API_Syslog.py --waf --activity --bots --user your_user@domain.com --password Password123! --interval 60000 --server 1.2.3.4 --port 5678 --transport tcp

