from protocol.icmp import *

from protocol.tcp import *
from protocol.udp import *

from protocol.dns import *
from protocol.http import *
from protocol.tls import *

import ipaddress
import random
import os


class PCAP:
    def __init__(self, rule, address, port, proto, src_ip, src_port, dst_ip, dst_port):
        self.rule       = rule
        self.address    = address
        self.port       = port

        self.src_ip     = self.gen_ip(src_ip)
        self.src_port   = self.gen_port(src_port)
        self.dst_ip     = self.gen_ip(dst_ip)
        self.dst_port   = self.gen_port(dst_port)

        if proto == 'ip': proto = 'udp'
        
        if proto.upper() in list(globals()):
            self.proto = globals()[proto.upper()](self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        else: self.proto = proto
        # else: print('Unsupported protocol : ', proto)

        self.sid        = 1000000
        self.content    = []
        self.flow       = []


    # generate IP
    def gen_ip(self, ip):
        if (ip == "any"): ip = self.random_ip()
        else:
            flag_dollar = 0
            while (ip.find('$') + 1):
                flag_dollar = 1
                for ad in list(self.address):
                    ip = ip.replace(f'${ad}', self.address[ad])

            flag_not = 0
            if flag_dollar:
                if ip[0] == '!':
                    flag_not = 1
                    ip = ip[1:]
                if ip.count('[') > 1: ip = ip.split(']')[0][1:] + ']'
                if flag_not: ip = '!' + ip

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
                    for ip in include:
                        if int(str(ip).split('.')[3]) and (not exclude or ip not in exclude): break
                        
                else:
                    ip = ipaddress.ip_network(self.random_ip())
                    while ip in exclude: ipaddress.ip_network(self.random_ip())
                ip = str(ip)

            elif ip.find('/') + 1:
                ip = str(random.choice(self.ip_slash(ip)))

        return self.ip2byte(ip)

    # generate all of IP list from subnet mask
    def ip_slash(self, ip):
        return list(ipaddress.ip_network(ip))

    # generate random IP
    def random_ip(self):
        return '.'.join([ str(random.randint(0,255)) for _ in range(4) ])

    # convert IP from decimal to hexadecimal 
    def ip2byte(self, ip):
        return b''.join([ bytes([int(i)]) for i in ip.split('.') ])

    # append two generator
    def add_generator(self, i, j):
        for x in j: yield x
        for x in i: yield x



    # generate port
    def gen_port(self, port):
        if (port == "any"): port = random.randint(1024,65535)
        else:
            while (port.find('$') + 1):
                for pt in list(self.port):
                    port = port.replace(f'${pt}', str(self.port[pt]))

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
    
    # generate port from given range
    def port_colon(self, value):
        delimiter_colon = value.find(':')
        if delimiter_colon + 1 == len(value): value += "65535"
        if not delimiter_colon: value = "1024" + value
        a, b = map(int, value.split(':'))
        return list(range(a, b))


    # generate header for pcap file
    def golbal_header(self):
        return \
            b'\xd4\xc3\xb2\xa1' + \
            b'\x02\x00' + \
            b'\x04\x00' + \
            b'\x00\x00\x00\x00' + \
            b'\x00\x00\x00\x00' + \
            b'\xff\xff\x00\x00' + \
            b'\x01\x00\x00\x00'


    # generate pcap from parsed informations
    def build(self, folder):
        filename = f'{folder}/{self.sid}.pcap'
        try:
            with open(filename, 'wb') as wb:
                wb.write(self.golbal_header())
                wb.write(self.proto.build())

        except AttributeError:
            os.remove(filename)
            print(f'Unsupported protocol: {self.rule.split(" ")[1]}')

        except Exception as e:
            os.remove(filename)
            print(f'Build error : {e}')
            print(f'{self.__dict__}')
            print()
