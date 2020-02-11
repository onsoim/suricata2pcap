from protocol.tcp import *

# class inheritance from 'TCP'
class TLS(TCP):
    def build(self, proto = 6):
        ''' build tls's header and data '''

        # build tls data
        self.content = b'\x17' + b'\x03\x03' + \
            (len(self.content)).to_bytes(2, 'big') + \
            b''.join(self.content)
        self.c_length = len(self.content)

        # build packet header
        c = self.packet_header(c_length = self.c_length)

        # Layer 2 (Ethernet)
        c += self.dst_mac + self.src_mac + b'\x08\x00'

        # Layer 3 (IP)
        c += b'\x45\x00' + (44 + self.c_length).to_bytes(2, 'big') + b'\x00\x01\x40\x00\x40' + bytes([proto]) + b'\xb6\xb2' + self.src_ip + self.dst_ip

        # Layer 4 (TCP)
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
