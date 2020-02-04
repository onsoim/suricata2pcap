from PCAP import *
from TAG import *

import re
import os


if __name__ == "__main__":
    # with open('rules/full_ruleset.rules', 'r') as r:
    with open('rules/test.rules', 'r') as r:
        rules = r.read().splitlines()

    tag_http = ['http_header', 'http_uri', 'http_method', 'http_user_agent', 'http_host']

    folder = './pcaps'
    if not os.path.isdir(folder): os.mkdir(folder)

    for rule in rules:
        # print(rule)

        # raw_rule = re.findall(r'([^()]+)$', rule)
        # raw_header = raw_rule[0].split(" ")
        delimiter_parentheses = rule.find('(')
        raw_header, raw_tags = [x for x in rule[:delimiter_parentheses - 1].split(' ') if x], rule[delimiter_parentheses + 1: -1]
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
                        if k == 'content':
                            if flag != 'dns_query': flag = 'content'
                            pcap.__dict__[k].append(v)
                        elif k == 'offset':
                            c_length = 0
                            for c in pcap.__dict__[flag][:-1]: c_length += len(c)
                            c = pcap.__dict__[flag][-1]
                            pcap.__dict__[flag][-1] = b'A' * (int(v) - c_length) + c
                        elif k == 'depth' or k == 'within':
                            c = pcap.__dict__[flag][-1]
                            if v.isdecimal(): pcap.__dict__[flag][-1] = b'A' * (int(v) - len(c)) + c
                            else: print(v, tag, rule)
                        elif k == 'distance':
                            c1, c2 = pcap.__dict__[flag][-2], pcap.__dict__[flag][-1]
                            if v.isdecimal(): 
                                del pcap.__dict__[flag][-1]
                                del pcap.__dict__[flag][-1]
                                pcap.__dict__[flag].append(c1 + b'A' * int(v) + c2)
                            else: print(v, tag, rule)
                        elif k == 'flow':
                            pcap.__dict__['flow'] = v
                        elif k == 'sid':
                            pcap.__dict__['sid'] = v
                        elif k == 'dns_query':
                            flag = 'dns_query'
                        else:
                            print(k, v)

                else:
                    # ret = TAG.__dict__[tag]()
                    if tag in tag_http:
                        flag = tag
                        pcap.__dict__[flag].append(pcap.__dict__['content'][-1])
                        del pcap.__dict__['content'][-1]
                    

            except KeyError:
                print(f'Unsupported keyword : {tag} - {rule}')

            except ValueError:
                print(f'Value Error : {tag} - {rule}')

            except Exception as e: print(e, tag)#, rule)

        print(f'{rule}\n{pcap.__dict__}\n====================')
        pcap.build()
