from PCAP import *
from TAG import *

import re

if __name__ == "__main__":
    with open('rules/test.rules', 'r') as r:
        rules = r.read().splitlines()

    for rule in rules:
        # raw_rule = re.findall(r'([^()]+)$', rule)
        # raw_header = raw_rule[0].split(" ")
        delimiter_parentheses = rule.find('(')
        raw_header, raw_tags = rule[:delimiter_parentheses - 1].split(' '), rule[delimiter_parentheses + 1: -1]
        pcap = PCAP(raw_header[1], raw_header[2], raw_header[3], raw_header[5], raw_header[6])

        # regex without pcre
        # tags = [ tag.group(0) for tag in re.finditer(r'([\w.]{1,})(:("[^"]*"|[^;]*);)?', raw_tags) ]
        tags = [ tag.group(0)[:-1] for tag in re.finditer(r'([\w.]{2,})(:("[^"]*"|[^;\\]*))?;', raw_tags) ]
        escape = raw_tags
        for tag in tags: escape =  escape.replace(f'{tag};', '')
        if escape.strip() != '': tags.append(escape.strip())

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
                            pcap.__dict__[k].append(v)
                        elif k == 'flow':
                            pcap.__dict__['flow'] = v
                        elif k == 'sid':
                            pcap.__dict__['sid'] = v
                        elif k == 'within':
                            c = pcap.__dict__['content'][-1]
                            pcap.__dict__['content'][-1] = b'A' * (int(v) - len(c)) + c
                        else:
                            print(k, v)

                else:
                    # ret = TAG.__dict__[tag]()
                    if tag == 'http_uri':
                        pcap.__dict__['http_uri'].append(pcap.__dict__['content'][-1])
                        del pcap.__dict__['content'][-1]

            except KeyError:
                print(f'unsupported keyword : {tag} - {rule}')

            except ValueError:
                print(f'Value Error : {tags} {rule}')

            except Exception as e: print(e, tag)

        print(pcap.__dict__)
