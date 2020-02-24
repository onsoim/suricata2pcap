import struct
from datetime import datetime

# This PROTOCOL class would be a skeleton class of any protocol
class PROTOCOL:
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip     = src_ip
        self.dst_ip     = dst_ip
        self.src_port   = src_port
        self.dst_port   = dst_port
        self.src_mac    = b'\x11\x11\x11\x11\x11\x11'
        self.dst_mac    = b'\x22\x22\x22\x22\x22\x22'

        self.content    = []
        self.c_length   = 0

        # print(self.__dict__)


    def packet_header(self, b_length = 58, c_length = 0):
        ''' build common packet's header '''
        
        return \
            struct.pack("<I", int(datetime.now().timestamp())) + \
            struct.pack("<I", datetime.now().microsecond) + \
            (b_length + c_length).to_bytes(4, 'little') + \
            (b_length + c_length).to_bytes(4, 'little')


    def build_content(self):
        self.content = b''.join(self.content)
        self.c_length = len(self.content)


    def calc_checksum(self, header, segment = b'', offset = -10):
        sum, padding = 0, b''

        if len(segment) % 2: padding = b'\x00'
        for x in struct.iter_unpack('!H', header + segment + padding): sum += x[0]
        if not len(segment): segment = header

        return segment[:offset] + (((sum >> 16) + (sum & 0xffff)) ^ 0xffff).to_bytes(2, 'big') + segment[offset + 2:]
