from protocol.protocol import *

class TCP(PROTOCOL):
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip     = src_ip
        self.dst_ip     = dst_ip
        self.src_port   = src_port
        self.dst_port   = dst_port
        self.src_mac    = b'\x11\x11\x11\x11\x11\x11'
        self.dst_mac    = b'\x22\x22\x22\x22\x22\x22'

        self.content    = []
        self.c_length   = 0
        self.flow       = []

        self.seq = 0
        self.ack = 0
        
        # print(self.__dict__)


    def handshake_3(self):
        c = self.packet_header()
        c += self.dst_mac + self.src_mac + b'\x08\x00'
        c += b'\x45\x00\x00\x2c\x00\x01\x00\x00\x40\x06\xb6\xb2' + self.src_ip + self.dst_ip
        c += self.src_port.to_bytes(2, 'big') + \
            self.dst_port.to_bytes(2, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            b'\x60\x02' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04\x00\x0e'

        self.seq += 1
        c += self.packet_header()
        c += self.src_mac + self.dst_mac + b'\x08\x00'
        c += b'\x45\x00\x00\x2c\x00\x01\x00\x00\x40\x06\xb6\xb2' + self.dst_ip + self.src_ip
        c += self.dst_port.to_bytes(2, 'big') + \
            self.src_port.to_bytes(2, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            b'\x60\x12' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04\x00\x0e'

        self.ack += 1
        c += self.packet_header()
        c += self.dst_mac + self.src_mac + b'\x08\x00'
        c += b'\x45\x00\x00\x2c\x00\x01\x00\x00\x40\x06\xb6\xb2' + self.src_ip + self.dst_ip
        c += self.src_port.to_bytes(2, 'big') + \
            self.dst_port.to_bytes(2, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            b'\x60\x10' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04\x00\x0e'

        return c


    def build(self, proto = 6):
        self.content = b''.join(self.content)
        self.c_length = len(self.content)

        c = self.packet_header(c_length = self.c_length)
        c += self.dst_mac + self.src_mac + b'\x08\x00'
        c += b'\x45\x00' + (44 + self.c_length).to_bytes(2, 'big') + b'\x00\x01\x40\x00\x40' + bytes([proto]) + b'\xb6\xb2' + self.src_ip + self.dst_ip
        c += self.src_port.to_bytes(2, 'big') + \
            self.dst_port.to_bytes(2, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            b'\x60\x18' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04' + \
            self.c_length.to_bytes(2, 'big')
        self.seq += self.c_length

        return self.handshake_3() + c + self.content + self.handshake_4()


    def handshake_4(self):
        c = self.packet_header()
        c += self.src_mac + self.dst_mac + b'\x08\x00'
        c += b'\x45\x00\x00\x2c\x00\x01\x00\x00\x40\x06\xb6\xb2' + self.dst_ip + self.src_ip
        c += self.dst_port.to_bytes(2, 'big') + \
            self.src_port.to_bytes(2, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            b'\x60\x10' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04\x00\x0e'
        
        c += self.packet_header()
        c += self.dst_mac + self.src_mac + b'\x08\x00'
        c += b'\x45\x00\x00\x2c\x00\x01\x00\x00\x40\x06\xb6\xb2' + self.src_ip + self.dst_ip
        c += self.src_port.to_bytes(2, 'big') + \
            self.dst_port.to_bytes(2, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            b'\x60\x11' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04\x00\x0e'

        self.seq += 1
        c += self.packet_header()
        c += self.src_mac + self.dst_mac + b'\x08\x00'
        c += b'\x45\x00\x00\x2c\x00\x01\x00\x00\x40\x06\xb6\xb2' + self.dst_ip + self.src_ip
        c += self.dst_port.to_bytes(2, 'big') + \
            self.src_port.to_bytes(2, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            b'\x60\x10' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04\x00\x0e'

        return c
