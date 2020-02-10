from PCAP import *
from TAG import *

import re
import os


def main():
    with open('rules/full_ruleset.rules', 'r') as r:
    # with open('rules/test.rules', 'r') as r:
        rules = r.read().splitlines()

    folder = './pcaps'
    if not os.path.isdir(folder): os.mkdir(folder)

    for rule in rules:
        # print(rule)

        # raw_rule = re.findall(r'([^()]+)$', rule)
        # raw_header = raw_rule[0].split(" ")
        delimiter_parentheses = rule.find('(')
        raw_header, raw_tags = [x for x in rule[:delimiter_parentheses - 1].split(' ') if x], rule[delimiter_parentheses + 1: -1]
        if raw_header[1].find('tcp') + 1 and raw_tags.find('http_') + 1: raw_header[1] = 'http'
        pcap = PCAP(raw_header[1], raw_header[2], raw_header[3], raw_header[5], raw_header[6])

        # regex without pcre
        # tags = [ tag.group(0) for tag in re.finditer(r'([\w.]{1,})(:("[^"]*"|[^;]*);)?', raw_tags) ]
        tags = [ tag.group(0)[:-1] for tag in re.finditer(r'([\w.]{2,})(:("[^"]*"|[^;\\]*))?;', raw_tags) ]
        escape = raw_tags
        for tag in tags: escape =  escape.replace(f'{tag};', '')
        if escape.strip() != '': tags.append(escape.strip())

        flag = ''
        for tag in tags:
            # try: globals()[k](v)
            try:
                delimiter_colon = tag.find(':')
                if delimiter_colon + 1:
                    k, v = tag[:delimiter_colon], tag[delimiter_colon + 1:]
                    delimiter_dot = k.find('.')
                    if delimiter_dot != -1: k = k.replace('.', '_')
                    ret = TAG.__dict__[k](v)
                    # if ret == None: print(k)
                    if ret != None:
                        k, v = list(ret.keys())[0], list(ret.values())[0]
                        if k == 'content' or k == 'pcre':
                            if flag != 'dns_query': flag = 'content'
                            pcap.proto.__dict__[flag].append(v)
                        elif k == 'offset':
                            c_length = 0
                            for c in pcap.proto.__dict__[flag][:-1]: c_length += len(c)
                            c = pcap.proto.__dict__[flag][-1]
                            pcap.proto.__dict__[flag][-1] = b'A' * (int(v) - c_length) + c
                        elif k == 'depth' or k == 'within':
                            c = pcap.proto.__dict__[flag][-1]
                            if v.isdecimal(): pcap.proto.__dict__[flag][-1] = b'A' * (int(v) - len(c)) + c
                            else: print(v, tag, rule)
                        elif k == 'distance':
                            c = pcap.proto.__dict__[flag][-1]
                            if v.isdecimal(): pcap.proto.__dict__[flag][-1] = b'A' * int(v) + c
                            else: print(v, tag, rule)
                        elif k == 'flow':
                            pcap.proto.__dict__['flow'] = v
                        elif k == 'isdataat':
                            if 'relative' in v:
                                del v[v.index('relative')]
                                if v[0][0] == '!': v = b'A' * (int(v[0][1:]) - 1)
                                else: v = b'A' * (int(v[0]))
                                # print('isdataat', pcap.proto.__dict__, flag, v)
                                pcap.proto.__dict__[flag][-1] += v
                            else:
                                c_length = 0
                                for c in pcap.proto.__dict__[flag]: c_length += len(c)
                                pcap.proto.__dict__[flag].append(b'A' * (int(v[0]) - c_length))
                        elif k in ['icode', 'itype']:
                            pcap.proto.__dict__[k] = v
                        elif k == 'sid':
                            pcap.sid = v
                        else:
                            print(k, v)

                else:
                    # ret = TAG.__dict__[tag]()
                    if 'http' in tag:
                        flag = tag
                        pcap.proto.__dict__[flag].append(pcap.proto.content[-1])
                        del pcap.proto.content[-1]
                    elif tag == 'dns_query':
                        flag = tag
                    

            except KeyError:
                print(f'Key keyword : {tag} - {rule}')

            except ValueError:
                print(f'Value Error : {tag} - {rule}')

            except Exception as e: print(f'Unknown Error : {e} / {tag} - {rule}')

            # print(tag, "\n", pcap.proto.__dict__)

        try: pcap.build()
        except Exception as e:
            print(f'Build error : {e} - {rule}')
            print(f'{pcap.__dict__}\n====================')


if __name__ == "__main__":
    main()