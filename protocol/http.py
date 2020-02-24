from protocol.tcp import *

# class inheritance from 'TCP'
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

        # below variables store raw value from a given rule
        self.http_client_body       = []
        self.http_cookie            = []
        self.http_header            = []
        self.http_server_body       = []
        self.http_stat_code         = []
        self.http_stat_msg          = []
        self.http_raw_header        = []
        self.http_raw_uri           = []

        # parsing value from above variables
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

        # default values if nothing coming in
        self.method            = b'GET'
        self.uri               = b'/'
        self.version           = b'HTTP/1.1'
        self.host              = b'Host: www.onsoim.com'
        self.connection        = b'Connection: keep-alive'
        self.upgrade_insecure_requests = b'Upgrade-Insecure-Requests: 1'
        self.user_agent        = b'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3945.130 Safari/537.36'
        self.accept            = b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
        self.accept_encoding   = b'Accept-Encoding: gzip, deflate'
        self.accept_language   = b'Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7'

        self.seq = 0
        self.ack = 0
        self.checksum = b'\x00\x00'

        # print(self.__dict__)

    
    def build_content(self):
        ''' build http's data '''

        # stage 1: http_* -> http_{var}
        for var in (list(self.__dict__)[9:17]):
            self.__dict__[var] = [ v for v in self.__dict__[var] if v ]
        #     for v in self.__dict__[var]:
        #         print(v, len(v))
        #         # onsoim: workon
        # # for h in self.http_header: self.__dict__[h[:h.decode().find(':')].decode().lower().replace('-', '_')] = h
        # print()

        # stage 2: http_{var} -> {var}
        for var in list(self.__dict__)[17:27]:
            if 'http' in var and len(self.__dict__[var]):
                self.__dict__[var[5:]] = b'-'.join([ v.capitalize().encode() for v in var[5:].split('_') ]) + b': ' + b''.join(self.__dict__[var])

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
