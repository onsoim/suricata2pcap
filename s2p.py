from PCAP import *
from TAG import *

from parsuricata import parse_rules
import re

standalone = [
    'ftpbounce',
    'nocase',
    'http_user_agent',
    'http_uri',
    'http_header',
    'http_method',
    'http_host',
    'fast_pattern',
    'http_client_body',
    'http_raw_header',
    'file_data',
    'http_stat_code',
    'http_raw_uri',

]

with open('full_ruleset.rules', 'r') as r:
    rules = r.read().splitlines()

for rule in rules[:10]:
    parsing = parse_rules(rule)
    print(parsing)
    # raw_rule = re.findall(r'([^()]+)$', rule)
    # raw_header = raw_rule[0].split(" ")
    # pcap = PCAP(raw_header[1], raw_header[2], raw_header[3], raw_header[5], raw_header[6])
    # print(pcap.__dict__)

    # delimiter = rule.find('(')
    # raw_header, raw_tags = rule[:delimiter - 1], rule[delimiter + 1: -1]

    # # tags = [ tag.group(0) for tag in re.finditer(r'([\w]{1,})(:("[^"]*"|[^;]*);)?', raw_tags) ]
    # tags = raw_tags.split('; ')

    # for tag in tags:
    #     # try: globals()[k](v)
    #     try:
    #         delimiter = tag.find(':')
    #         if delimiter + 1:
    #             k,v = tag[:delimiter], tag[delimiter + 1:]
    #             TAG.__dict__[k](v)
    #         else:
    #             TAG.__dict__[tag]()

    #     except KeyError:
    #         print(f'unsupported keyword : {tag} {rule}')

    #     except ValueError:
    #         if (tag in standalone):
    #             TAG.__dict__[tag]()
    #         else:
    #             test = tag.split(':')
    #             print(f'Value Error : {test} {tags} {rule}')

    #     except Exception as e: print(e, tag)