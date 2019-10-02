#Kaitlyn Whipple
#September 29, 2019
#IT&C 567

#The following code allows the user to select a host using a domain name, a single IP address, an IP address with a subnet mask, or a list of IPs from a text file. The user can choose to scan a single or range of ports. The user can request to run a UDP scan; otherwise, the default is TCP. The verbose option allows users to see which port is currently being scanned; otherwise, they see only open ports. Once the scan is completed, the user sees how long it took. They also have the option of viewing the results in a PDF report.
#Example commands: portscanner.py -d localhost -rng 440-445 -0f coolreport -v; portscanner.py -sub 192.168.1.0/24 -prt 443;
