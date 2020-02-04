from protocol.protocol import *

class TCP(PROTOCOL):
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
        c = self.packet_header(self.c_length)
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

        return c + self.content


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
