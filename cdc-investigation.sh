#!/bin/bash
red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`

echo "/*********************************************************/
/* LOG4J Investigation                                   */
/* Author: CDC                                           */
/* Last updated on: Dec 2021                             */
/*********************************************************/"

echo "/=========================================================/
/ Objective: Scanning for exploit attempts                /
/ ${red}Instruction: Look for JNDI strings in the log output${reset}    /
/=========================================================/"

echo "scanning /var directory for exploit attempts..."
timeout -s SIGKILL 10s sudo grep -RnsI /var -e 'jndi:' '${::-j}' | grep -v "Error looking up JNDI" | grep -v "COMMAND"
echo "scanning /opt directory for exploit attempts"
timeout -s SIGKILL 10s sudo grep -RnsI /opt -e 'jndi' '${::-j}' | grep -v "Error looking up JNDI"

echo "/==============================================================/
/ Objective: Scanning for successful callbacks                 /
/ ${red}Instruction: The result may indicate that host was exploited${reset} /
/==============================================================/"

timeout -s SIGKILL 10s sudo grep -RInsE '(\J\N\D\I).*\b[0-9]{1,3}.\b[0-9]{1,3}.\b[0-9]{1,3}.\b[0-9]{1,3}:[0-9]{1,3}\b|(\J\N\D\I).*([\w+.]{1,}[a-z]{1,3}:[0-9]{2,5}\b)' /var | grep -v "grep -RInsE"

timeout -s SIGKILL 10s sudo grep -RInsE '(\J\N\D\I).*\b[0-9]{1,3}.\b[0-9]{1,3}.\b[0-9]{1,3}.\b[0-9]{1,3}:[0-9]{1,3}\b|(\J\N\D\I).*([\w+.]{1,}[a-z]{1,3}:[0-9]{2,5}\b)' /opt | grep -v "grep -RInsE"

echo "/====================================================================/
/ Objective: Scanning for Java process making network connections    /
/ ${red}Instruction: Java making network connection to an unkown IP/Domain /
/              may should investigated properly${reset}                       /
/====================================================================/"
ps -ef | grep -P '[0-9+]+(\.[0-9]+){3}(:[0-9]+\/)|\w+[.]\w{1,3}:[0-9]{2,5}[\/]+|\w+[.]\w{2,3}\/'

echo "/====================================================================/
/ Objective: Fetching active network connections to the public IP    /
/ ${red}Instruction: Host making network connection to an unkown IP/Domain /
/              may should investigated properly${reset}                     /
/====================================================================/"

sudo netstat -tnp  | grep -v 169.254.169.254 | grep -v 127.0.0.1 | grep -P '(\d+)(?<!10)\.(\d+)(?<!192\.168)(?<!172\.(1[6-9]|2\d|3[0-1]))\.(\d+)\.(\d+)[/:]'
