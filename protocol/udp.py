from protocol.protocol import *

class UDP(PROTOCOL):
    def packet_header(self, length = 0):
        return \
            struct.pack("<I", int(datetime.now().timestamp())) + \
            struct.pack("<I", datetime.now().microsecond) + \
            (42 + length).to_bytes(4, 'little') + \
            (42 + length).to_bytes(4, 'little')


    def build(self, proto = 6):
        c = self.packet_header(self.c_length)
        c += self.dst_mac + self.src_mac + b'\x08\x00'
        c += b'\x45\x00' + (28 + self.c_length).to_bytes(2, 'big') + b'\x00\x01\x40\x00\x40' + bytes([proto]) + b'\xb6\xb2' + self.src_ip + self.dst_ip
        c += self.src_port.to_bytes(2, 'big') + \
            self.dst_port.to_bytes(2, 'big') + \
            (8 + self.c_length).to_bytes(2, 'big') + \
            b'\x00\x00'

        return c + self.content
