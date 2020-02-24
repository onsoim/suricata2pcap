from protocol.protocol import *

# class inheritance from 'PROTOCOL'
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


    def build(self):
        ''' build icmp's header and data '''

        self.build_content()

        c = self.packet_header(b_length = 42, c_length = len(self.content))

        # build layer 2 (Ethernet)
        c += \
            self.dst_mac + \
            self.src_mac + \
            b'\x08\x00'

        # build layer 3 (IP)
        c += self.calc_checksum(
            b'\x45\x00' + \
            (28 + self.c_length).to_bytes(2, 'big') + \
            b'\x00\x00' + \
            b'\x00\x00' + \
            b'\x80\x01' + \
            b'\x00\x00' + \
            self.src_ip + \
            self.dst_ip
        )

        # build layer 4 (ICMP)
        c += self.calc_checksum(
            bytes([self.itype]) + \
            bytes([self.icode]) + \
            b'\x00\x00' + \
            b'\x00\x00' + \
            b'\x00\x00' + \
            self.content,
            offset = 2
        )
        
        return c
