from protocol.protocol import *

# class inheritance from 'PROTOCOL'
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
        self.checksum = b'\x00\x00'
        
        # print(self.__dict__)


    def handshake_3(self):
        c = self.packet_header()
        c += self.dst_mac + self.src_mac + b'\x08\x00'
        c += self.calc_checksum(b'\x45\x00\x00\x2c\x00\x01\x00\x00\x40\x06' + self.checksum + self.src_ip + self.dst_ip)
        c += self.tcp_checksum(
            self.src_ip + self.dst_ip + b'\x00\x06' + (24).to_bytes(2, 'big'),
            self.src_port.to_bytes(2, 'big') + \
            self.dst_port.to_bytes(2, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            b'\x60\x02' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04\x00\x0e'
        )

        self.seq += 1
        c += self.packet_header()
        c += self.src_mac + self.dst_mac + b'\x08\x00'
        c += self.calc_checksum(b'\x45\x00\x00\x2c\x00\x01\x00\x00\x40\x06' + self.checksum + self.dst_ip + self.src_ip)
        c += self.tcp_checksum(
            self.src_ip + self.dst_ip + b'\x00\x06' + (24).to_bytes(2, 'big'),
            self.dst_port.to_bytes(2, 'big') + \
            self.src_port.to_bytes(2, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            b'\x60\x12' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04\x00\x0e'
        )

        self.ack += 1
        c += self.packet_header()
        c += self.dst_mac + self.src_mac + b'\x08\x00'
        c += self.calc_checksum(b'\x45\x00\x00\x2c\x00\x01\x00\x00\x40\x06' + self.checksum + self.src_ip + self.dst_ip)
        c += self.tcp_checksum(
            self.src_ip + self.dst_ip + b'\x00\x06' + (24).to_bytes(2, 'big'),
            self.src_port.to_bytes(2, 'big') + \
            self.dst_port.to_bytes(2, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            b'\x60\x10' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04\x00\x0e'
        )

        return c


    def build(self, proto = 6):
        ''' build tcp's header and data '''

        self.build_content()

        hand3 = self.handshake_3()

        # build packet header
        c = self.packet_header(c_length = self.c_length)

        # build layer 2 (Ethernet)
        c += self.dst_mac + self.src_mac + b'\x08\x00'

        # build layer 3 (IP)
        c += self.calc_checksum(b'\x45\x00' + (44 + self.c_length).to_bytes(2, 'big') + b'\x00\x01\x40\x00\x40' + bytes([proto]) + self.checksum + self.src_ip + self.dst_ip)

        # build layer 4 (TCP)
        c += self.calc_checksum(
            self.src_ip + self.dst_ip + b'\x00\x06' + (24 + self.c_length).to_bytes(2, 'big'),
            self.src_port.to_bytes(2, 'big') + \
            self.dst_port.to_bytes(2, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            b'\x60\x18' + \
            self.c_length.to_bytes(2, 'big') + \
            self.checksum + b'\x00\x00' + b'\x02\x04' + \
            self.c_length.to_bytes(2, 'big') + \
            self.content,
            16
        )
        self.seq += self.c_length

        hand4 = self.handshake_4()

        if 'established' in self.flow: return hand3 + c + hand4
        return c


    def handshake_4(self):
        c = self.packet_header()
        c += self.src_mac + self.dst_mac + b'\x08\x00'
        c += self.calc_checksum(b'\x45\x00\x00\x2c\x00\x01\x00\x00\x40\x06' + self.checksum + self.dst_ip + self.src_ip)
        c += self.tcp_checksum(
            self.src_ip + self.dst_ip + b'\x00\x06' + (24).to_bytes(2, 'big'),
            self.dst_port.to_bytes(2, 'big') + \
            self.src_port.to_bytes(2, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            b'\x60\x10' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04\x00\x0e'
        )

        c += self.packet_header()
        c += self.dst_mac + self.src_mac + b'\x08\x00'
        c += self.calc_checksum(b'\x45\x00\x00\x2c\x00\x01\x00\x00\x40\x06' + self.checksum + self.src_ip + self.dst_ip)
        c += self.tcp_checksum(
            self.src_ip + self.dst_ip + b'\x00\x06' + (24).to_bytes(2, 'big'),
            self.src_port.to_bytes(2, 'big') + \
            self.dst_port.to_bytes(2, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            b'\x60\x11' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04\x00\x0e'
        )

        self.seq += 1
        c += self.packet_header()
        c += self.src_mac + self.dst_mac + b'\x08\x00'
        c += self.calc_checksum(b'\x45\x00\x00\x2c\x00\x01\x00\x00\x40\x06' + self.checksum + self.dst_ip + self.src_ip)
        c += self.tcp_checksum(
            self.src_ip + self.dst_ip + b'\x00\x06' + (24).to_bytes(2, 'big'),
            self.dst_port.to_bytes(2, 'big') + \
            self.src_port.to_bytes(2, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            b'\x60\x10' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04\x00\x0e'
        )

        return c


    def tcp_checksum(self, pseudo_header, tcp_segment):
        sum, padding = 0, b''

        if len(tcp_segment) % 2: padding = b'\x00'
        for x in struct.iter_unpack('!H', pseudo_header + tcp_segment + padding): sum += x[0]
        
        return tcp_segment[:16] + (((sum >> 16) + (sum & 0xffff)) ^ 0xffff).to_bytes(2, 'big') + tcp_segment[18:]
