import binascii
import rstr
from xeger import Xeger


def findall(str, sub):
    index = []
    start = 0
    while True:
        start = str.find(sub, start)
        if start == -1: return index
        index.append(start)
        start += len(sub)
    

class TAG:
    def content(value):
        flag = False
        if value[0] == '!':
            value = value[1:]
            flag = True
        value = value.strip('"')
        delimiter_bar = findall(value, '|')
        c = b''
        
        if not len(delimiter_bar): c += bytes(value, "utf-8")
        else:
            c += bytes(value[:delimiter_bar[0]], "utf-8")
            for i in range(0, len(delimiter_bar), 2):
                for b in value[delimiter_bar[i] + 1: delimiter_bar[i+1]].split(' '):
                    if len(b) % 2: b = '0' + b
                    if b != "": c += binascii.unhexlify(b)
                try: c += bytes(value[delimiter_bar[i+1] + 1 : delimiter_bar[i+2]], "utf-8")
                except:
                    if delimiter_bar[i+1] < len(value) - 1:
                        c += bytes(value[delimiter_bar[i+1] + 1 : len(value)], "utf-8")
        if flag: c = c[::-1]
        # print(f'content "{value}" -> {c}')
        return {'content': c}

    def pcre(value):
        ret, cnt = None, 10
        while ret == None and cnt:
            try: ret = rstr.xeger(value[value.find('/') + 1: value.rfind('/')])
            except:
                try: ret = Xeger().xeger(value[value.find('/') + 1: value.rfind('/')])
                except: cnt -= 1
        # print(f'pcre "{value}" -> {ret.encode()}')
        if ret == None: print('Failed to generate pcre.')
        else: return {'pcre': ret.encode()}
        

    def depth(value):       return {'depth': value.strip()}
    def distance(value):    return {'distance': value.strip()}
    def icode(value):       return {'icode': int(value.strip())}
    def isdataat(value):    return {'isdataat': [ v.strip() for v in value.split(',') ]}
    def itype(value):       return {'itype': int(value.strip())}
    def flow(value):        return {'flow': value.strip().split(',')}
    def within(value):      return {'within': value.strip()}
    def offset(value):      return {'offset': value.strip()}
    def sid(value):         return {'sid': value.strip()}

    def classtype(value):   pass
    def metadata(value):    pass
    def msg(value):         pass
    def reference(value):   pass
    def rev(value):         pass
    def threshold(value):   pass


    def flowbits(value):
        # print("flowbits :", value)
        pass
    
    def flags(value):
        # print("flags :", value)
        pass

    def byte_test(value):
        # print("byte_test :", value)
        pass

    def byte_jump(value):
        # print("byte_jump :", value)
        pass

    def dsize(value):
        # print("dsize :", value)
        pass

    def tag(value):
        # print("tag :", value)
        pass

    def fast_pattern(*value):
        # print("fast_pattern :", value)
        pass

    def asn1(value):
        # print("asn1 :", value)
        pass

    def uricontent(value):
        # print("uricontent :", value)
        pass

    def urilen(value):
        # print("urilen :", value)
        pass

    def ip_proto(value):
        # print("ip_proto :", value)
        pass
        
    def detection_filter(value):
        # print("detection_filter :", value)
        pass

    def icmp_id(value):
        # print("icmp_id :", value)
        pass

    def byte_extract(value):
        # print("byte_extract :", value)
        pass

    def ssl_version(value):
        # print("ssl_version :", value)
        pass

    def ssl_state(value):
        # print("ssl_state :", value)
        pass

    def softwareversion(value):
        # print("softwareversion :", value)
        pass

    def stream_size(value):
        # print("stream_size :", value)
        pass

    def id(value):
        # print("id :", value)
        pass

    def ssh_softwareversion(value):
        # print("ssh_softwareversion :", value)
        pass

    def ftpbounce():
        # print("ftpbounce")
        pass

    def http_client_body():
        # print("http_client_body")
        pass

    def http_raw_header():
        # print("http_raw_header")
        pass

    def file_data():
        # print("file_data")
        pass

    def http_stat_code():
        # print("http_stat_code")
        pass

    def http_raw_uri():
        # print("http_raw_uri")
        pass

    def http_cookie():
        # print("http_cookie")
        pass

    def dns_query():
        # print("dns_query")
        pass

    def http_stat_msg():
        # print("http_stat_msg")
        pass

    def http_server_body():
        # print("http_server_body")
        pass

    def rawbytes():
        # print("rawbytes")
        pass
