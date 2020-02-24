from protocol.udp import *

# class inheritance from 'UDP'
class DNS(UDP):
    def build(self, proto = 17):
        ''' build DNS's header and dns_query '''
        
        # convert normal string to dns format string
        self.content = b''.join(self.content)
        for l in self.content.split(b'.'):
            if len(l): self.content += bytes([len(l)]) + l
            else: self.content += b'\x03www'
        self.content = self.content[self.c_length:]

        # build dns query
        self.content = b'\x00\x00' + \
            b'\x01\x00' + \
            b'\x00\x01' + \
            b'\x00\x00' + \
            b'\x00\x00' + \
            b'\x00\x00' + \
            self.content + \
            b'\x00' + \
            b'\x00\x01' + \
            b'\x00\x01'
        self.c_length = len(self.content)

        self.dst_port = 53

        # build packet header
        c = self.packet_header(c_length = self.c_length)

        # build layer 2 (Ethernet)
        c += self.dst_mac + self.src_mac + b'\x08\x00'

        # build layer 3 (IP)
        c += b'\x45\x00' + (28 + self.c_length).to_bytes(2, 'big') + b'\x00\x01\x00\x00\x40' + bytes([proto]) + b'\x00\x00' + self.src_ip + self.dst_ip

        # build layer 4 (UDP)
        c += self.src_port.to_bytes(2, 'big') + \
            self.dst_port.to_bytes(2, 'big') + \
            (8 + self.c_length).to_bytes(2, 'big') + \
            b'\x12\x34'

        return c + self.content
