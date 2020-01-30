import random
import struct
from ICMP import *
from TCP import *
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


        self.src_ip = self.gen_ip(src_ip)
        self.src_port = self.gen_port(src_port)
        self.dst_ip = self.gen_ip(dst_ip)
        self.dst_port = self.gen_port(dst_port)
        self.proto = proto

        self.sid        = 1000000
        self.content    = []
        self.flow       = []

        self.http_header        = []
        self.http_host          = []
        self.http_method        = []
        self.http_uri           = []
        self.http_user_agent    = []


    def gen_ip(self, ip):
        flag = False
        if ip[0] == '!':
            ip = ip[1:]
            flag = True

        if ip[0] == '[':
            ip = random.choice(ip[1:-1].split(','))

        if ip[0] == '!':
            ip = ip[1:]
            flag = True

        if (ip == "any"): ip = self.random_ip()
        elif (ip == "$DNS_SERVERS"): ip = "192.168.0.1"
        elif (ip == "$HOME_NET"): ip = "192.168.0.1"
        elif (ip == "$HTTP_SERVERS"): ip = "192.168.0.1"
        elif (ip == "$SMTP_SERVERS"): ip = "192.168.0.1"
        elif (ip == "$SQL_SERVERS"): ip = "192.168.0.1"
        elif (ip == "$EXTERNAL_NET"): ip = "20.0.0.1"

        # if flag: print(list(ipaddress.ip_network('0.0.0.0/0').address_exclude(ipaddress.ip_network(ip))))
        if (ip.find('/') + 1): ip = str(random.choice(list(ipaddress.ip_network(ip).hosts())))
        ip = self.ip2byte(ip)

        return ip


    def random_ip(self):
        return '.'.join([ str(random.randint(0,255)) for _ in range(4) ])

    def ip2byte(self, ip):
        return b''.join([bytes([int(i)]) for i in ip.split('.')])


    def gen_port(self, port):
        if (port == "any"): port = random.randint(1024,65535)
        else:
            port = port.replace("$HTTP_PORTS", '80')
            port.replace("$ORACLE_PORTS", '80')
            port.replace("$SSH_PORTS", '80')

            if (port[0] == '!'):
                port = port[1:]
                exclude = []
                if (port[0] == '['):
                    for ex in port[1:-1].split(','):
                        if ex.find(':') + 1: exclude += self.port_colon(ex)
                        else: exclude.append(int(ex))

                elif port.find(':') + 1:
                    exclude += self.port_colon(port)
                
                else: exclude.append(int(port))

                port = random.choice(list(set(list(range(1024,65535))).difference(set(exclude))))

            elif (port[0] == '['):
                include, exclude  = [], []
                for ex in port[1:-1].split(','):
                    if ex[0] == '!':
                        ex = ex[1:]
                        exclude.append(int(ex))
                    elif ex.find(':') + 1: include += self.port_colon(ex)
                    else: include.append(int(ex))
                if not len(include): include = self.port_colon(':')
                port = random.choice(list(set(include).difference(set(exclude))))

            elif (port.find(':') + 1):
                port = random.choice(self.port_colon(port))

        return int(port)
    

    def port_colon(self, value):
        delimiter_colon = value.find(':')
        if delimiter_colon + 1 == len(value): value += "65535"
        if not delimiter_colon: value = "1024" + value
        a, b = map(int, value.split(':'))
        return list(range(a, b))


    def build(self):
        with open(f'pcaps/{self.sid}.pcap', 'wb') as wb:
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
