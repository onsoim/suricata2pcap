from protocol.tcp import *

class HTTP(TCP):
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

        self.http_client_body       = []
        self.http_cookie            = []
        self.http_header            = []
        self.http_stat_code         = []
        self.http_stat_msg          = []
        self.http_raw_header        = []
        self.http_raw_uri           = []

        self.http_method            = []
        self.http_uri               = []
        self.http_version           = []
        self.http_host              = []
        self.http_connection        = []
        self.http_upgrade_insecure_requests = []
        self.http_user_agent        = []
        self.http_accept            = []
        self.http_accept_encoding   = []
        self.http_accept_language   = []

        self.method            = b'GET'
        self.uri               = b'/'
        self.version           = b'HTTP/1.1'
        self.host              = b'Host: www.google.com'
        self.connection        = b'Connection: keep-alive'
        self.upgrade_insecure_requests = b'Upgrade-Insecure-Requests: 1'
        self.user_agent        = b'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3945.130 Safari/537.36'
        self.accept            = b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
        self.accept_encoding   = b'Accept-Encoding: gzip, deflate'
        self.accept_language   = b'Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7'

        self.seq = 0
        self.ack = 0
        
        # print(self.__dict__)

    
    def build_http(self):
        for h in self.http_header: self.__dict__[h[:h.decode().find(':')].decode().lower().replace('-', '_')] = h

        self.content = b' '.join([self.method, self.uri, self.version]) + b'\r\n' + \
            self.host + b'\r\n' + \
            self.connection + b'\r\n' + \
            self.upgrade_insecure_requests + b'\r\n' + \
            self.user_agent + b'\r\n' + \
            self.accept + b'\r\n' + \
            self.accept_encoding + b'\r\n' + \
            self.accept_language + b'\r\n' + \
            b'\r\n'
        self.c_length = len(self.content)


    def build(self):
        self.build_http()

        c = self.packet_header(c_length = self.c_length)
        c += self.dst_mac + self.src_mac + b'\x08\x00'
        c += b'\x45\x00' + (44 + self.c_length).to_bytes(2, 'big') + b'\x00\x01\x40\x00\x40\x06\xb6\xb2' + self.src_ip + self.dst_ip
        c += self.src_port.to_bytes(2, 'big') + \
            self.dst_port.to_bytes(2, 'big') + \
            self.seq.to_bytes(4, 'big') + \
            self.ack.to_bytes(4, 'big') + \
            b'\x60\x18' + \
            self.c_length.to_bytes(2, 'big') + \
            b'\x00\x00' + b'\x00\x00' + b'\x02\x04' + \
            self.c_length.to_bytes(2, 'big')
        self.seq += self.c_length
        
        if "established" not in self.flow: return c + self.content
        return self.handshake_3() + c + self.content + self.handshake_4()
