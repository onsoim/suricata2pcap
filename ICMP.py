class ICMP:
    def __init__(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_mac = b'\x00\x00\x00\x00\x00\x00'
        self.dst_mac = b'\x00\x00\x00\x00\x00\x00'

        # self.build_packet_data()
        # print(self.packet_data)

    def build_packet_data(self):
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
            src_ip + \
            dst_ip

        self.packet_data = \
            self.ethernet_frame + \
            self.ip_frame + \
            self.itype + \
            self.icode + \
            b'\x00\x00' + \
            b'\x00\x00' + \
            b'\x00\x00' + \
            content            

# src_ip = b'\xc0\xa8\x00\x01'
# dst_ip = b'\xc0\xa8\x00\x01'
# src_mac = b'\xdd\xee\xff\x44\x55\x66'
# dst_mac = b'\xaa\xbb\xcc\x11\x22\x33'
# itype = 8
# icode = 0

# icmp = ICMP(src_ip, dst_ip, src_mac, dst_mac)#, itype, icode)