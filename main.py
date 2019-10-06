import sys, argparse
import re
import ipaddress
from scapy.all import *
from prettytable import PrettyTable

def main():
    # [[ipAddress, {type :[open, ports] }], ...]
    results = []
    parser = argparse.ArgumentParser(description='Prowler: the sneaky port scanner')
    parser.add_argument('hosts', nargs="+", help="the host to be scanned")
    parser.add_argument('-p', '--ports', required=True, nargs="+", help='the port to be scanned')
    parser.add_argument('-s', '--scan', required=True, nargs="+", choices=['udp', 'tcp', 'icmp'], help="Preform a ICMP scan")

    args = parser.parse_args()
    print("Beginning Scan")
    preformScans(args, results)
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
                    openTcpPorts.append(port)
            hostResult[host]['udp'] = openUdpPorts 
                 
        if ('icmp' in args.scan):
            hostResult[host]['icmp'] = [ icmpScan(host)]

        results.append(hostResult)


def tcpScan(host, port):
    response = sr1(IP(dst=host)/TCP(dport=port,flags="S"), timeout=1, verbose=0)
    if response != None and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 'SA':
            return True
    return False

def udpScan(host, port):
    response = send(IP(dst=host)/UDP(dport=port), verbose=0)
    if response != None and response.haslayer(UDP):
        return True
    return False 

def icmpScan(host):
    response = sr1(IP(dst=host)/ICMP(), verbose=0)
    if (response != None and response.haslayer(ICMP)):
        return response.getlayer(ICMP).type == 0
    return False

def printScanResult(args, results):
    table = PrettyTable()
    headers = []
    if ('tcp' in args.scan):
        headers.append('Open TCP Ports')
    if ('udp' in args.scan):
        headers.append('Open UDP Ports')
    if('icmp' in args.scan):
        headers.append('ICMP Reponse')
    table.field_names = headers
    for host in results:
        hostName = list(host.keys())[0]
        data = getTabularData(host[hostName])
        for row in data:
            table.add_row(row)
        print(hostName)
        print(table)

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

def traceRoute(): 
    pass



if __name__ == "__main__":
    main()