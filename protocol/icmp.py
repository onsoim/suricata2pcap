from protocol.protocol import *

class ICMP(PROTOCOL):
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip     = src_ip
        self.dst_ip     = dst_ip
        self.src_port   = src_port
        self.dst_port   = dst_port
        self.src_mac    = b'\x11\x11\x11\x11\x11\x11'
        self.dst_mac    = b'\x22\x22\x22\x22\x22\x22'

        self.content    = []

        self.itype      = 8
        self.icode      = 0

        # print(self.__dict__)


    def build(self, content = b''):
        self.ethernet_frame = \
            self.dst_mac + \
            self.src_mac + \
            b'\x08\x00'

        self.ip_frame = \
            b'\x45' + \
            b'\x00' + \
            b'\x00\x9c' + \
            b'\x00\x00' + \
            b'\x00\x00' + \
            b'\x2b' + \
            b'\x01' + \
            b'\x22\x03' + \
            self.src_ip + \
            self.dst_ip

        self.content = b''.join(self.content)

        self.packet_data = \
            self.packet_header(b_length = 42, c_length = len(self.content)) + \
            self.ethernet_frame + \
            self.ip_frame + \
            bytes([self.itype]) + \
            bytes([self.icode]) + \
            b'\x00\x00' + \
            b'\x00\x00' + \
            b'\x00\x00' + \
            self.content
        
        return self.packet_data
