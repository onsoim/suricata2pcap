from protocol.protocol import *

class UDP(PROTOCOL):
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip     = src_ip
        self.dst_ip     = dst_ip
        self.src_port   = src_port
        self.dst_port   = dst_port
        self.src_mac    = b'\x11\x11\x11\x11\x11\x11'
        self.dst_mac    = b'\x22\x22\x22\x22\x22\x22'

        self.content    = []
        self.c_length   = 0

        self.checksum = b'\x00\x00'

        # print(self.__dict__)


    def build(self, proto = 17):
        ''' build udp's header and data '''

        self.build_content()

        # build packet header
        c = self.packet_header(b_length = 42, c_length = self.c_length)

        # build layer 2 (Ethernet)
        c += self.dst_mac + self.src_mac + b'\x08\x00'

        # build layer 3 (IP)
        c += self.calc_checksum(b'\x45\x00' + (28 + self.c_length).to_bytes(2, 'big') + b'\x00\x01\x40\x00\x40' + bytes([proto]) + self.checksum + self.src_ip + self.dst_ip)

        # build layer 4 (UDP)
        c += self.calc_checksum(
            self.src_ip + self.dst_ip + b'\x00' + bytes([proto]) + (8 + self.c_length).to_bytes(2, 'big'),
            self.src_port.to_bytes(2, 'big') + \
            self.dst_port.to_bytes(2, 'big') + \
            (8 + self.c_length).to_bytes(2, 'big') + \
            b'\x00\x00' + \
            self.content,
            6
        )

        return c


