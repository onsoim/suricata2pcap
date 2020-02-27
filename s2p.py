from builder.PCAP import *
from builder.OPTION import *

import re
import os
import yaml
import argparse


def build(args):
    with open(args.config) as f: groups = yaml.load(f, Loader=yaml.SafeLoader)['vars']
    address, port = groups['address-groups'], groups['port-groups']

    rules = []
    for f in [ f'{args.rules}/{f}' for f in os.listdir(args.rules) if '.rules' in f ] if os.path.isdir(args.rules) else [args.rules]:
        with open(f, 'r') as r:
            rules += r.read().splitlines()

    # output folder for generated pcaps
    folder = args.output
    if not os.path.isdir(folder): os.mkdir(folder)

    for rule in rules:
        # raw_header stores 'action' and 'header' / raw_options stores all 'option'
        delimiter_parentheses = rule.find('(')
        raw_header, raw_options = [x for x in rule[:delimiter_parentheses - 1].split(' ') if x], rule[delimiter_parentheses + 1: -1]
        if raw_header[1].find('tcp') + 1 and raw_options.find('http_') + 1: raw_header[1] = 'http'

        # consturct PCAP object with 'rule', 'address info from yaml', 'port info from yaml', 'protocol', 'source ip', 'source port', 'destination ip', 'destination port'
        pcap = PCAP(rule, address, port, raw_header[1], raw_header[2], raw_header[3], raw_header[5], raw_header[6])

        # extract all options without pcre from a given rule to the list 'options' and add pcre option seperately
        options = [ option.group(0)[:-1] for option in re.finditer(r'([\w.]{2,})(:("[^"]*"|[^;\\]*))?;', raw_options) ] 
        escape = raw_options
        for option in options: escape =  escape.replace(f'{option};', '')
        if escape.strip() != '': options.append(escape.strip())

        # flag stores a target where to put the content like dns_query
        flag = 'content'
        for option in options:
            try:
                delimiter_colon = option.find(':')
                # if the option is consisting of key and value
                if delimiter_colon + 1:
                    k, v = option[:delimiter_colon], option[delimiter_colon + 1:]

                    # some key has a dot in its name so replace it to under bar
                    delimiter_dot = k.find('.')
                    if delimiter_dot != -1: k = k.replace('.', '_')

                    ret = OPTION.__dict__[k](v)
                    if ret != None:
                        k, v = list(ret.keys())[0], list(ret.values())[0]
                        
                        if k == 'content' or k == 'pcre':
                            flag = 'content'
                            pcap.proto.__dict__[flag].append(v)

                        elif k == 'offset':
                            c_length = 0
                            for c in pcap.proto.__dict__[flag][:-1]: c_length += len(c)
                            c = pcap.proto.__dict__[flag][-1]
                            pcap.proto.__dict__[flag][-1] = b'A' * (int(v) - c_length) + c

                        elif k == 'depth' or k == 'within':
                            c = pcap.proto.__dict__[flag][-1]
                            if v.isdecimal(): pcap.proto.__dict__[flag][-1] = b'A' * (int(v) - len(c)) + c
                            else: print(v, option, rule)

                        elif k == 'distance':
                            c = pcap.proto.__dict__[flag][-1]
                            if v.isdecimal(): pcap.proto.__dict__[flag][-1] = b'A' * int(v) + c
                            else: print(v, option, rule)

                        elif k == 'isdataat':
                            if 'relative' in v:
                                del v[v.index('relative')]
                                if v[0][0] == '!': v = b'A' * (int(v[0][1:]) - 1)
                                else: v = b'A' * (int(v[0]))
                                pcap.proto.__dict__[flag][-1] += v
                            else:
                                c_length = 0
                                for c in pcap.proto.__dict__[flag]: c_length += len(c)
                                pcap.proto.__dict__[flag].append(b'A' * (int(v[0]) - c_length))

                        elif k in ['flow', 'icode', 'itype']:
                            pcap.proto.__dict__[k] = v

                        elif k == 'sid':
                            pcap.sid = v

                        else:
                            print(k, v)

                # if the option is standalone
                else:
                    # options related to http
                    if 'http' in option:
                        flag = option
                        pcap.proto.__dict__[flag].append(pcap.proto.content[-1])
                        del pcap.proto.content[-1]
                    
            except KeyError:
                print(f'Key Error : {option} - {rule}')

            except ValueError:
                print(f'Value Error : {option} - {rule}')

            except AttributeError: pass

            except Exception as e: print(f'Unknown Error : {e} / {option} - {rule}')

        # build a pcap with parsed options
        pcap.build(args.output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(dest = "config", help = "Suricata config file")
    parser.add_argument(dest = "rules", help = 'Suricata rule file or folder')
    parser.add_argument('-o', '--output', dest = "output", default = 'pcaps', help = 'the name of output folder (defalt: pcaps)')
    args = parser.parse_args()

    build(args)


if __name__ == "__main__":    
    main()