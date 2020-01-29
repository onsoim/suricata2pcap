import random
import struct
from datetime import datetime
from ICMP import *
from TCP import *
import os
import ipaddress

class PCAP:
    def __init__(self, proto, src_ip, src_port, dst_ip, dst_port):
        self.golbal_header = \
            b'\xd4\xc3\xb2\xa1' + \
            b'\x02\x00' + \
            b'\x04\x00' + \
            b'\x00\x00\x00\x00' + \
            b'\x00\x00\x00\x00' + \
            b'\xff\xff\x00\x00' + \
            b'\x01\x00\x00\x00'


        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        self.sid        = 1000000
        self.content    = []
        self.flow       = []

        self.http_header        = []
        self.http_host          = []
        self.http_method        = []
        self.http_uri           = []
        self.http_user_agent    = []

        self.gen_ip()
        self.gen_port()

        
        self.proto = proto


    def gen_ip(self):
        flag = False
        if self.src_ip[0] == '!':
            self.src_ip = self.src_ip[1:]
            flag = True

        if self.src_ip[0] == '[':
            self.src_ip = random.choice(self.src_ip[1:-1].split(','))

        if self.src_ip[0] == '!':
            self.src_ip = self.src_ip[1:]
            flag = True

        if (self.src_ip == "any"): self.src_ip = self.random_ip()
        elif (self.src_ip == "$DNS_SERVERS"): self.src_ip = "192.168.0.1"
        elif (self.src_ip == "$HOME_NET"): self.src_ip = "192.168.0.1"
        elif (self.src_ip == "$HTTP_SERVERS"): self.src_ip = "192.168.0.1"
        elif (self.src_ip == "$SMTP_SERVERS"): self.src_ip = "192.168.0.1"
        elif (self.src_ip == "$SQL_SERVERS"): self.src_ip = "192.168.0.1"
        elif (self.src_ip == "$EXTERNAL_NET"): self.src_ip = "20.0.0.1"

        # if flag: print(list(ipaddress.ip_network('0.0.0.0/0').address_exclude(ipaddress.ip_network(self.src_ip))))
        if (self.src_ip.find('/') + 1): self.src_ip = str(random.choice(list(ipaddress.ip_network(self.src_ip).hosts())))
        self.src_ip = self.ip2byte(self.src_ip)

        #############################################
        #############################################
        #############################################
        flag = False
        if self.dst_ip[0] == '!':
            self.dst_ip = self.dst_ip[1:]
            flag = True

        if self.dst_ip[0] == '[':
            self.dst_ip = random.choice(self.dst_ip[1:-1].split(','))

        if self.dst_ip[0] == '!':
            self.dst_ip = self.dst_ip[1:]
            flag = True

        if (self.dst_ip == "any"): self.dst_ip = self.random_ip()
        elif (self.dst_ip == "$DNS_SERVERS"): self.dst_ip = "192.168.0.1"
        elif (self.dst_ip == "$HOME_NET"): self.dst_ip = "192.168.0.1"
        elif (self.dst_ip == "$HTTP_SERVERS"): self.dst_ip = "192.168.0.1"
        elif (self.dst_ip == "$SMTP_SERVERS"): self.dst_ip = "192.168.0.1"
        elif (self.dst_ip == "$SQL_SERVERS"): self.dst_ip = "192.168.0.1"
        elif (self.dst_ip == "$EXTERNAL_NET"): self.dst_ip = "20.0.0.1"

        if (self.dst_ip.find('/') + 1): self.dst_ip = str(random.choice(list(ipaddress.ip_network(self.dst_ip).hosts())))
        self.dst_ip = self.ip2byte(self.dst_ip)


    def random_ip(self):
        return '.'.join([ str(random.randint(0,255)) for _ in range(4) ])

    def ip2byte(self, ip):
        return b''.join([bytes([int(i)]) for i in ip.split('.')])

    def gen_port(self):
        if (self.src_port == "any"): self.src_port = random.randint(1024,65535)
        elif (self.src_port == "$HTTP_PORTS"): self.src_port = 80
        
        if (self.dst_port == "any"): self.dst_port = random.randint(1024,65535)
        elif (self.dst_port == "$HTTP_PORTS"): self.dst_port = 80
        
    def build(self):
        folder = f'./pcaps_{int(datetime.now().timestamp())}'
        if not os.path.isdir(folder): os.mkdir(folder)
        with open(f'{folder}/{self.sid}.pcap', 'wb') as wb:
            wb.write(self.golbal_header)
            
            if self.proto == "tcp":
                tcp = TCP(self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.content)
                if "established" in self.flow:
                    wb.write(tcp.handshake_3())

                wb.write(tcp.build())

                if "established" in self.flow:
                    wb.write(tcp.handshake_4())

            if self.proto == "icmp":
                self.proto = ICMP(self.src_ip, self.dst_ip)
                wb.write(self.proto.build_packet_data('8', '0', b'\x0a\x0a'))
