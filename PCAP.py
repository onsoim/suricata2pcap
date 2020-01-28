import random
import struct
from datetime import datetime
from ICMP import *

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

        if proto == "icmp": self.proto = ICMP(self.src_ip, self.dst_ip)
        else: self.proto = proto


    def gen_ip(self):
        if (self.src_ip == "any"): self.src_ip = self.random_ip()
        elif (self.src_ip == "$HOME_NET"): self.src_ip = "192.168.0.1"
        elif (self.src_ip == "$HTTP_SERVERS"): self.src_ip = "192.168.0.1"
        elif (self.src_ip == "$EXTERNAL_NET"): self.src_ip = "20.0.0.1"

        if (self.dst_ip == "any"): self.dst_ip = self.random_ip()
        elif (self.dst_ip == "$HOME_NET"): self.dst_ip = "192.168.0.1"
        elif (self.dst_ip == "$HTTP_SERVERS"): self.dst_ip = "192.168.0.1"
        elif (self.dst_ip == "$EXTERNAL_NET"): self.dst_ip = "20.0.0.1"

        self.src_ip = self.ip2byte(self.src_ip)
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

    def packet_header(self):
        return \
            struct.pack("<I", int(datetime.now().timestamp())) + \
            struct.pack("<I", datetime.now().microsecond) + \
            b'\x3a\x00\x00\x00' + \
            b'\x3a\x00\x00\x00'
        
    def build(self):
        with open(f'{self.sid}.pcap', 'wb') as wb:
            wb.write(self.golbal_header)
            wb.write(self.packet_header())
