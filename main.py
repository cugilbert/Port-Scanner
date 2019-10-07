import sys, argparse
import re
import ipaddress
from scapy.all import *
from prettytable import PrettyTable

# Reads a range from the command line - 5
# Put in subnet mask and will scan the subnet -5 
# Allow multiple ports to be scanned -10
# Also includes TCP, UDP, and IMCP scans 15
# Pdf creation 10

def main():
    # [[ipAddress, {type :[open, ports] }], ...]
    results = []
    parser = argparse.ArgumentParser(description='Prowler: the sneaky port scanner')
    parser.add_argument('hosts', nargs="+", help="the hosts to be scanned")
    parser.add_argument('-p', '--ports', required=True, nargs="+", help='the port to be scanned')
    parser.add_argument('-s', '--scan', required=True, nargs="+", choices=['udp', 'tcp', 'icmp'], help="Preform a ICMP scan")
    parser.add_argument('-f', '--file', required=False, action="store_true", help="Output results to a file")

    args = parser.parse_args()
    print("Beginning Scan. This may take a while...")
    preformScans(args, results)
    print('Scan completed')
    printScanResult(args, results)

def getPorts(ports):
    allPorts = []

    for port in ports:
        if (port.find("-") != -1):
            rangeNumbers = [int(newPort) for newPort in port.split('-')]
            if (len(rangeNumbers) > 2):
                raise Exception('Invalid port range %s' % port)
            allPorts = allPorts + list(range(rangeNumbers[0], rangeNumbers[1] + 1))
        else:
            allPorts.append(int(port))
    
    return allPorts


def getIpAddresses(ipAddresses):
    allHosts = []

    for ip in ipAddresses:
        for subnetIp in ipaddress.IPv4Network(ip, strict=False):
            allHosts.append(str(subnetIp))

    return allHosts
    
def preformScans(args, results):    
    ports = getPorts(args.ports)
    hosts = getIpAddresses(args.hosts)
    print(hosts)
    for host in hosts:
        print("Scanning %s" % host)
        hostResult = {host: {}}
        if ('tcp' in args.scan): 
            openTcpPorts = []         
            for port in ports:
                if (tcpScan(host, port)):
                    openTcpPorts.append(port)
            hostResult[host]['tcp'] = openTcpPorts 
        if ('udp' in args.scan ):
            openUdpPorts = []         
            for port in ports:
                if (udpScan(host, port)):
                    openUdpPorts.append(port)
            hostResult[host]['udp'] = openUdpPorts 
                 
        if ('icmp' in args.scan):
            hostResult[host]['icmp'] = [ icmpScan(host)]

        results.append(hostResult)


def tcpScan(host, port):
    response = sr1(IP(dst=host)/TCP(dport=port,flags="S"), timeout=0.5, verbose=0)
    if response != None and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 'SA':
            return True
    return False

def udpScan(host, port):
    response = sr1(IP(dst=host)/UDP(dport=port), timeout=5, verbose=0)
    if response != None and response.haslayer(ICMP):
        return False
    
    return True

def icmpScan(host):
    response = sr1(IP(dst=host)/ICMP(), timeout=0.5, verbose=0)
    if (response != None and response.haslayer(ICMP)):
        return response.getlayer(ICMP).type == 0
    return False

def printScanResult(args, results):
    
    headers = []
    if ('tcp' in args.scan):
        headers.append('Open TCP Ports')
    if ('udp' in args.scan):
        headers.append('Open UDP Ports')
    if('icmp' in args.scan):
        headers.append('ICMP Reponse')
    
    output = ''
    for host in results:
        table = PrettyTable()
        table.field_names = headers
        hostName = list(host.keys())[0]
        data = getTabularData(host[hostName])
        for row in data:
            table.add_row(row)
        print(hostName)
        print(table)
        output += hostName + "\n" + table.get_string() + "\n"
    if (args.file):
        fileOut(output)
        output = ''

def fileOut(data):
    f = open("./scan_results.txt","w+")
    f.write(data)
    f.close() 

def getTabularData(hostResults):
    tabularData = []
    scans = []
    if ('tcp' in hostResults):
        scans.append(hostResults['tcp'])
    if ('udp' in hostResults):
        scans.append(hostResults['udp'])
    if ('icmp' in hostResults):
        scans.append(hostResults['icmp'])

    while (sum(len(items) for items in scans) > 0):
        row = [] 
        for scan in scans:           
            if (len(scan) > 0):
                row.append(scan.pop(0))
            else:
                row.append('')
        tabularData.append(row)    
    return tabularData

if __name__ == "__main__":
    main()