from protocol.icmp import *

from protocol.tcp import *
from protocol.udp import *

from protocol.dns import *
from protocol.http import *
from protocol.tls import *

import ipaddress
import random


class PCAP:
    def __init__(self, proto, src_ip, src_port, dst_ip, dst_port):
        self.src_ip     = self.gen_ip(src_ip)
        self.src_port   = self.gen_port(src_port)
        self.dst_ip     = self.gen_ip(dst_ip)
        self.dst_port   = self.gen_port(dst_port)

        # if proto.upper() in list(globals()) + ['IP']:
        #     self.proto = globals()[proto.upper()](self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        # else: print('unsupported protocol : ', proto)
        self.proto      = proto

        self.sid        = 1000000
        self.content    = []
        self.flow       = []

        self.http_header        = []
        self.http_host          = []
        self.http_method        = []
        self.http_uri           = []
        self.http_user_agent    = []

        self.dns_query  = []
        self.itype      = 8
        self.icode      = 0



    def gen_ip(self, ip):
        if (ip == "any"): ip = self.random_ip()
        else:
            ip = ip.replace("$AIM_SERVERS", '192.168.0.1')
            ip = ip.replace("$DNS_SERVERS", '192.168.0.1')
            ip = ip.replace("$HOME_NET", '192.168.0.1')
            ip = ip.replace("$HTTP_SERVERS", '192.168.0.1')
            ip = ip.replace("$SMTP_SERVERS", '192.168.0.1')
            ip = ip.replace("$SQL_SERVERS", '192.168.0.1')
            ip = ip.replace("$TELNET_SERVERS", '192.168.0.1')

            ip = ip.replace("$EXTERNAL_NET", '20.0.0.1')
            
            if ip[0] == '!':
                ip = ip[1:]
                exclude = [ip]
                while ip in exclude: ip = self.random_ip()

            elif ip[0] == '[':
                include, exclude = None, None
                for ex in ip[1:-1].split(','):
                    if ex.find('!') + 1:
                        ex = ex[1:]
                        if not exclude: exclude = ipaddress.ip_network(ex, strict=False)
                        else: exclude = self.add_generator(exclude, ipaddress.ip_network(ex, strict=False))
                    else: 
                        if not include: include = ipaddress.ip_network(ex, strict=False)
                        else: include = self.add_generator(include, ipaddress.ip_network(ex, strict=False))

                if include:
                    include = list(include)
                    random.shuffle(include)
                    for ip in include:
                        if not exclude or ip not in exclude: break
                else:
                    ip = ipaddress.ip_network(self.random_ip())
                    while ip in exclude: ipaddress.ip_network(self.random_ip())
                ip = str(ip)

            elif ip.find('/') + 1:
                ip = str(random.choice(list(ipaddress.ip_network(ip))))

        return self.ip2byte(ip)


    def random_ip(self):
        return '.'.join([ str(random.randint(0,255)) for _ in range(4) ])

    def ip2byte(self, ip):
        return b''.join([ bytes([int(i)]) for i in ip.split('.') ])

    def add_generator(self, i, j):
        for x in i: yield x
        for x in j: yield x


    def gen_port(self, port):
        if (port == "any"): port = random.randint(1024,65535)
        else:
            port = port.replace("$HTTP_PORTS", '80')
            port = port.replace("$ORACLE_PORTS", '80')
            port = port.replace("$SHELLCODE_PORTS", '80')
            port = port.replace("$SSH_PORTS", '80')

            include, exclude = [], []
            delimiter_braket = port.find('[')
            if delimiter_braket + 1:
                if not delimiter_braket: 
                    for ex in port[1:-1].split(','):
                        if ex[0] == '!': exclude.append(int(ex[1:]))
                        elif ex.find(':') + 1:
                            include += self.port_colon(ex)
                        else: include.append(int(ex))

                else:
                    for ex in port[2:-1].split(','):
                        if ex.find(':') + 1: exclude += self.port_colon(ex)
                        else: exclude.append(int(ex))
                    
            elif port.find(',') + 1:
                for ex in port.split(','):
                    if port.find('!') + 1: exclude.append(port[1:])

            elif port.find(':') + 1:
                if port.find('!') + 1: port = random.choice(list(set(list(range(1024,65535))).difference(set(self.port_colon(port[1:])))))
                else: port = random.choice(self.port_colon(port))

            elif port.find('!') + 1: port = random.choice(list(set(list(range(1024,65535))).difference(set([port[1:]]))))

            if len(exclude) or len(include):
                if not len(include): include = self.port_colon(':')
                port = random.choice(list(set(include).difference(set(exclude))))

        return int(port)
    

    def port_colon(self, value):
        delimiter_colon = value.find(':')
        if delimiter_colon + 1 == len(value): value += "65535"
        if not delimiter_colon: value = "1024" + value
        a, b = map(int, value.split(':'))
        return list(range(a, b))


    def golbal_header(self):
        return \
            b'\xd4\xc3\xb2\xa1' + \
            b'\x02\x00' + \
            b'\x04\x00' + \
            b'\x00\x00\x00\x00' + \
            b'\x00\x00\x00\x00' + \
            b'\xff\xff\x00\x00' + \
            b'\x01\x00\x00\x00'


    def build(self):
        with open(f'pcaps/{self.sid}.pcap', 'wb') as wb:
            if self.proto.upper() in list(globals()) + ['IP']:
                wb.write(self.golbal_header())
                
                if self.proto == "tcp":
                    tcp = TCP(self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.content)
                    if "established" in self.flow:
                        wb.write(tcp.handshake_3())

                    wb.write(tcp.build())

                    if "established" in self.flow:
                        wb.write(tcp.handshake_4())

                elif self.proto == "tls":
                    tls = TLS(self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.content)
                    if "established" in self.flow:
                        wb.write(tls.handshake_3())

                    wb.write(tls.build())

                    if "established" in self.flow:
                        wb.write(tls.handshake_4())

                elif self.proto == "http":
                    http = HTTP(self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.content)
                    if "established" in self.flow:
                        wb.write(http.handshake_3())

                    http_dict = {}
                    for h in ['http_user_agent']:
                        if self.__dict__[h]:
                            http_dict[h] = b''.join(self.__dict__[h])
                    wb.write(http.build(**http_dict))

                    if "established" in self.flow:
                        wb.write(http.handshake_4())

                elif self.proto == "udp" or self.proto == "ip":
                    self.proto = UDP(self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.content)
                    wb.write(self.proto.build(proto = 17))

                elif self.proto == "icmp":
                    self.proto = ICMP(self.src_ip, self.dst_ip)

                    wb.write(self.proto.build(itype = self.itype, icode = self.icode, content = b'\x0a\x0a'))
                
                elif self.proto == "dns":
                    self.proto = DNS(self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.dns_query)
                    wb.write(self.proto.build())

            # else: print('unsupported protocol : ', self.proto)
