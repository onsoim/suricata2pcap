import random

class PCAP:
    def __init__(self, proto, src_ip, src_port, dst_ip, dst_port):
        self.proto = proto
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = src_port

        self.content = []
        self.flow = []
        self.http_uri = []
        self.sid = 1000000

        self.gen_ip()
        self.gen_port()
    

    def gen_ip(self):
        if (self.src_ip == "any"): self.src_ip = self.random_ip()
        elif (self.src_ip == "$HOME_NET"): self.src_ip = "192.168.0.1"
        elif (self.src_ip == "$EXTERNAL_NET"): self.src_ip = "20.0.0.1"

        if (self.dst_ip == "any"): self.dst_ip = self.random_ip()
        elif (self.dst_ip == "$HOME_NET"): self.dst_ip = "192.168.0.1"
        elif (self.dst_ip == "$EXTERNAL_NET"): self.dst_ip = "20.0.0.1"

    def random_ip(self):
        return ':'.join([ str(random.randint(0,255)) for _ in range(4) ])

    def gen_port(self):
        if (self.src_port == "any"): self.src_port = random.randint(1024,65535)
        if (self.dst_port == "any"): self.dst_port = random.randint(1024,65535)