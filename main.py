import sys, argparse
from scapy.all import sr1,IP,ICMP

def main():
    parser = argparse.ArgumentParser(description='Prowler: the sneaky port scanner')
    parser.add_argument('Host', help="the host to be scanned")
    parser.add_argument('Port', help='the port to be scanned')
    parser.add_argument('-t', '--tcp', action='store_false', help="preform a tcp scan")
    parser.add_argument('-u', '--udp', action='store_true', help="preform a udp scan")
    args = parser.parse_args()
    

if __name__ == "__main__":
    main()