import struct
from datetime import datetime

class PROTOCOL:
    def __init__(self, src_ip, src_port, dst_ip, dst_port, content):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_mac = b'\x11\x11\x11\x11\x11\x11'
        self.dst_mac = b'\x22\x22\x22\x22\x22\x22'

        self.content = b''.join(content)
        self.c_length = len(self.content)

        self.seq = 0
        self.ack = 0

        print(self.__dict__)


    def packet_header(self, length = 0):
        return \
            struct.pack("<I", int(datetime.now().timestamp())) + \
            struct.pack("<I", datetime.now().microsecond) + \
            (58 + length).to_bytes(4, 'little') + \
            (58 + length).to_bytes(4, 'little')
    