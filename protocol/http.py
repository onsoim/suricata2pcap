from protocol.tcp import *

class HTTP(TCP):
    def build(
        self,
        http_method             = b'GET',
        http_uri                = b'/',
        http_version            = b'HTTP/1.1',
        http_host               = b'www.google.com',
        http_connection         = b'keep-alive',
        http_upgrade_insecure_requests  = b'1',
        http_user_agent         = b'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3945.130 Safari/537.36',
        http_accept             = b'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        http_accept_encoding    = b'gzip, deflate',
        http_accept_language    = b'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
    ):
        # params = list(locals())
        # params.remove('self')
        # for param in params:
        #     if not locals()[param]: print(locals()[param])
        #     # print(param, len(locals()[param]), globals()[param.upper()])
        #     # if not len(locals()[param]): var = globals()[param.upper()]
        #     # else: var = b''.join(locals()[param])
        self.content = b' '.join([http_method, http_uri, http_version]) + b'\r\n' + \
            b'Host: ' + http_host + b'\r\n' + \
            b'Connection: ' + http_connection + b'\r\n' + \
            b'Upgrade_Insecure_Requests: ' + http_upgrade_insecure_requests + b'\r\n' + \
            b'User_Agent: ' + http_user_agent + b'\r\n' + \
            b'Accept: ' + http_accept + b'\r\n' + \
            b'Accept_Encoding: ' + http_accept_encoding + b'\r\n' + \
            b'Accept_Language: ' + http_accept_language + b'\r\n' + \
            b'\r\n'

        self.c_length = len(self.content)
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
        
        return c + self.content
