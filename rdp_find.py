#!/usr/bin/python
# coding=utf-8

import random
import threading
import argparse
from socket import *
import socket

# Arguments
parser = argparse.ArgumentParser(description="RDP Crack\n\nAuthor: vaf\nGithub: https://github.com/lonelyvaf\nOICQ: "
                                             " 1775787275",
                                 formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-i', help='File containing a list of IP addresses to check(example:-i ips.txt)')
parser.add_argument('-p', help='Number of connection ports (default port:3000-3389)', default='3380-3389')
parser.add_argument('-ips', help='The range of IP address block (example:179.64.0.0-179.191.35.255 )')
parser.add_argument('-threads', help="Number of connection threads when checking file of IPs (default 200)",
                    default=200)
txt_turn_on =False
ips_turn_on =False

args = parser.parse_args()
if args.i:
    filename = args.i
    txt_turn_on =True
if args.ips:
    ips = args.ips
    ips_turn_on =True
num_threads = int(args.threads)
semaphore = threading.BoundedSemaphore(value=num_threads)
print_lock = threading.Lock()
port_list = []
ports =  args.p
#port mix
n,m =ports.split("-")
for line in range(int(n), int(m)+1):
    port_list.append(line)
port_lists = random.sample(port_list, int(m)-int(n))

#print_status
def print_status(ip, message, msg_type='*'):
    global print_lock
    with print_lock:
        print "[%s] %s - %s" % (msg_type, ip, message)

#create ips
class gen_ip:
    def __init__(self,ip):
        self.ip = ip
    def gen_ip(self):
        start,end = [self.ip2num(x) for x in self.ip.split('-')]
        ip_list=  [self.num2ip(num) for num in  range(start,end+1) if num & 0xff]
        return ip_list
    def ip2num(self,ip):
        ip = [int(x) for x in ip.split('.')]
        return  ip[0]<<24 |ip[1]<<16 |ip[2]<<8 |ip[3]
    def num2ip(self,num):
        return '%s.%s.%s.%s'%( (num & 0xff000000) >>24,
                                (num & 0x00ff0000) >>16,
                                (num & 0x0000ff00) >>8,
                                 num & 0x000000ff
                               )
#rdp recognize
def run(target):
    global semaphore

    suc = False
    for port in port_list:
        if suc:
            break
        scan = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        scan.settimeout(2)

        if port:
            address=(target,int(port))
            try:
                scan.connect(address)
                scan.send('\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00')
                banner = scan.recv(5)
                print_status(target, str(port) + "--:" + str(banner))

                if banner == '\x03\x00\x00\x13\x0e':
                    print_status(target, "RDP Open![%s]" % str(port))
                    suc = True
                    with open('rdp_success.txt', 'a') as fs:
                        fs.write("%s:%s\n" % (target, str(port)))
                    continue
                else:
                    print_status(target, "RDP Close![%s] %s" % (str(port), banner))

            except Exception as e:
                print_status(target, str(e) + " ,port:" + str(port), "ERROR")
            finally:
                pass
        scan.close()
    semaphore.release()

def main():
    if txt_turn_on:
        with open(filename, "r") as fp:
            for ip in fp.xreadlines():
                semaphore.acquire()
                t = threading.Thread(target=run, args=(ip.strip(),))
                t.start()
    elif ips_turn_on:
        iplist = gen_ip(ips)
        iplist = iplist.gen_ip()
        for ip in iplist:
            semaphore.acquire()
            t = threading.Thread(target=run, args=(ip,))
            t.start()
    else:
        print "[*]usage:rdp_find.py -h"
if __name__ == "__main__":
    main()
