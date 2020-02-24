from protocol.tcp import *

# class inheritance from 'TCP'
class TLS(TCP):
    def build_content(self):
        self.content = b''.join(self.content)

        return b'\x17' + b'\x03\x03' + \
            (len(self.content)).to_bytes(2, 'big') + \
            self.content
