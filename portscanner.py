#Kaitlyn Whipple
#September 29, 2019
#IT&C 567

#The following code allows the user to select a host using a domain name, a single IP address, an IP address with a subnet mask, or a list of IPs from a text file. The user can choose to scan a single or range of ports. The user can request to run a UDP scan; otherwise, the default is TCP. The verbose option allows users to see which port is currently being scanned; otherwise, they see only open ports. Once the scan is completed, the user sees how long it took. They also have the option of viewing the results in a PDF report.
#Example commands: portscanner.py -d localhost -rng 440-445 -0f coolreport -v; portscanner.py -sub 192.168.1.0/24 -prt 443;

import socket
import subprocess
import sys
import argparse
from datetime import datetime
from fpdf import FPDF
import ipaddress


#function to scan a range of ports. Prints results to sceen and returns list
def findrange(hostIP, inputrange, protocol, verbose):
    list = []
    try:
        inputrange = inputrange.split("-", 2)
        portrange1 = int(inputrange[0])
        portrange2 = int(inputrange[1]) + 1
        for port in range(portrange1,portrange2):
            #checks if user requested UDP. Otherwise, default is TCP
            if protocol == 1:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                protname = "UDP"
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                protname = "TCP"
            #If verbose, user will see each port as it is scanned. Otherwise, they see only open ports.
            if verbose == 1:
                print ("Now scanning port ", port)
            result = sock.connect_ex((hostIP, port))
            if result == 0:
                print("Port {}: Open ({})".format(port, protname))
                list.append(port)
            sock.close()
        return list
    except socket.gaierror:
        print ('Hostname could not be resolved. Exiting')
        sys.exit()
    except socket.error:
        print ("Couldn't connect to server")
        sys.exit()
    except ValueError:
        print("Please enter data in correct format.")
    
#function to scan a single port. Prints results to sceen and returns list
def findsingle(hostIP, inputport, protocol):
    try:
        list = []
        inputport = int(inputport)
        #checks if user requested UDP. Otherwise, default is TCP
        if protocol == 1:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            protname = "UDP"
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            protname = "TCP"
        result = sock.connect_ex((hostIP, inputport))
        if result == 0:
            print("Port {}: Open ({})".format(inputport, protname))
            list.append(inputport)
        sock.close()
        return list
    except socket.gaierror:
        print ('Hostname could not be resolved. Exiting')
        sys.exit()
    except socket.error:
        print ("Couldn't connect to server")
        sys.exit()
    except ValueError:
        print("Please enter data in correct format.")


#Prints scan results to pdf
def printpdf(hostIP, portlist, filename, ports):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    #Formatted heading for report that displays the IP address, ports scanned, and date 
    pdf.cell(200, 10, txt="-"*60, ln=1, align="C")
    pdf.cell(200, 10, txt="Scan results for host {}".format(hostIP), ln=1, align="C")
    pdf.cell(200, 10, txt="Ports scanned: {}".format(ports), ln=1, align="C")
    pdf.cell(200, 10, txt="Date: {}".format(datetime.now()), ln=1, align="C")
    pdf.cell(200, 10, txt="-"*60, ln=1, align="C")
    #Loops through each result from scan
    for x in portlist:
        pdf.cell(200, 10, txt="Port {}: Open".format(x), ln=1)
    pdf.output("{}.pdf".format(filename))

        
def main():
    
    #arguements from command line
    parser = argparse.ArgumentParser()
    parser.add_argument("-d","--domain", help="Enter a host to scan. Ex. www.google.com")
    parser.add_argument("-IP","--IPaddress", help="Enter an IP address to scan. Ex. 127.0.0.1")
    parser.add_argument("-sub","--subnet", help="Enter IP address with subnet mask to scan.")
    parser.add_argument("-if","--ifile", help="Enter the name of a text file with IP addresses to scan. Addresses must be separated by a single space. Ex. list.txt")
    parser.add_argument("-prt","--port", help="Enter a single port number. Ex. 443")
    parser.add_argument("-rng","--range", help="Enter a range of ports. Ex. 440-445")
    parser.add_argument("-of","--ofile", help="Enter a name for the pdf report. Ex. Myreport")
    parser.add_argument("--UDP", help="Uses UDP if true", action="store_true")
    parser.add_argument("-v","--verbose", help="Displays ports while scanning. Otherwise, displays only open ports", action="store_true")
    args = parser.parse_args()

    #Set default values for protocol and verbose
    protocol = 0
    verbose = 0
    if args.UDP:
        protocol = 1
    if args.verbose:
        verbose = 1
    
    #Establishes host to scan. User has three optios: domain name, single IP, or IP with subnet mask.
    IPlist = []
    if args.domain:
        hostIP = args.domain
        hostIP = socket.gethostbyname(hostIP)
        IPlist.append(hostIP)
    elif args.IPaddress:
        hostIP = args.IPaddress
        hostIP = socket.gethostbyname(hostIP)
        IPlist.append(hostIP)
    elif args.subnet:
        subnet = args.subnet
        net4 = ipaddress.ip_network(subnet)
        #Creates list of IPs 
        for x in net4.hosts():
            IPlist.append(str(x))
    elif args.ifile:
        input = open(args.ifile, "r")
        input = input.read()
        IPlist = input.split()
    else:
        print("No host specified. Exiting")
        sys.exit()
    

    #Check what time the scan started
    t1 = datetime.now()
    
    #Loops through list of IP addresses and runs scan
    for x in IPlist:
        print ("-" * 30)
        print("Scanning host {}".format(x))
        print ("-" * 30)
        #If user selected range of ports, runs scun
        if args.range:
            portrange = args.range
            reportports = args.range
            portlist = findrange(x, portrange, protocol, verbose)
        #if user selected single port, runs scan
        elif args.port:
            port = args.port
            reportports = args.port
            portlist = findsingle(x, port, protocol)
        else:
            print("No ports specified. Exiting")
            sys.exit()
     
    # Checking the time again
    t2 = datetime.now()
    # Calculates how long it took to scan the ports
    total =  t2 - t1
    # Printing the information to screen
    print ('Scan Completed in: ', total)
    
    #Prints pdf of results if selected by user
    if args.ofile:
        filename = args.ofile
        printpdf(IPlist[0], portlist, filename, reportports)
        print("File created: {}.pdf".format(filename))
    
main()