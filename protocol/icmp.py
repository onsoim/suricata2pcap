class ICMP:
    def __init__(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_mac = b'\x11\x11\x11\x11\x11\x11'
        self.dst_mac = b'\x22\x22\x22\x22\x22\x22'

        # self.build_packet_data()
        # print(self.packet_data)

    def build(self, itype, icode, content):
        self.ethernet_frame = \
            self.dst_mac + \
            self.src_mac + \
            b'\x08\x00'

        self.ip_frame = \
            b'\x45' + \
            b'\x00' + \
            b'\x00\x9c' + \
            b'\x00\x00' + \
            b'\x00\x00' + \
            b'\x2b' + \
            b'\x01' + \
            b'\x22\x03' + \
            self.src_ip + \
            self.dst_ip

        self.packet_data = \
            self.ethernet_frame + \
            self.ip_frame + \
            bytes([int(itype)]) + \
            bytes([int(icode)]) + \
            b'\x00\x00' + \
            b'\x00\x00' + \
            b'\x00\x00' + \
            content
        
        return self.packet_data
