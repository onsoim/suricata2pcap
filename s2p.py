from PCAP import *
from TAG import *

import re

with open('rules/full_ruleset.rules', 'r') as r:
    rules = r.read().splitlines()

for rule in rules:
    # raw_rule = re.findall(r'([^()]+)$', rule)
    # raw_header = raw_rule[0].split(" ")
    # pcap = PCAP(raw_header[1], raw_header[2], raw_header[3], raw_header[5], raw_header[6])
    # print(pcap.__dict__)

    delimiter_parentheses = rule.find('(')
    raw_header, raw_tags = rule[:delimiter_parentheses - 1], rule[delimiter_parentheses + 1: -1]

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
                k,v = tag[:delimiter_colon], tag[delimiter_colon + 1:]
                delimiter_dot = k.find('.')
                if delimiter_dot != -1: k = k.replace('.', '_')
                TAG.__dict__[k](v)
            else:
                TAG.__dict__[tag]()

        except KeyError:
            print(f'unsupported keyword : {tag} - {rule}')

        except ValueError:
            print(f'Value Error : {tags} {rule}')

        except Exception as e: print(e, tag)