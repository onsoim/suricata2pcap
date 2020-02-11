import struct
from datetime import datetime

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
    