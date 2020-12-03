# Shodan_showdown
Python application that allows you to quickly scan specific IP ranges and grab banners from specific ports. Uses tools from the ZMap project that must be installed as a prerequisite. 

## Prerequisites
### ZMap
```bash
sudo apt-get install zmap
```
Any issues, check out https://github.com/zmap/zmap

### ZGrab2
See installation information at https://github.com/zmap/zgrab2

## Running the script
You will need root privileges to run this application at its full capacity; this is due to the ZMap and ZGrab2 applications requiring root privileges. It is recommended to elevate to a root account before running the application, rather than sudo.
```
$ su
Password: 
# python3 showdown.py 
showdown.py!
Type help if you.... need help?
>> help
show command:		
show opt[ions]/conf[ig]		Display current scan configuration		
show res[ults] [X]		Display [up to X] results of latest ZMap scan		
show grab			Display latest ZGrab Result		

set command:		
set port X			Set port number you want to find		
set ip X.X.X.X			Set specific IP address to scan		
set ip_range X.X.X.X/XX		Set IP range using CIDR Notation		
set freq[uency] X		Set frequency of requests per second		
set verb[osity] X		Set verbosity level of zmap		
set max X			Set max number of hosts to find in scan		

run command:		
run				Run ZMap scan with current configuration		

grab command:		
grab				Run ZGrab scan with latest results
>> 
```
