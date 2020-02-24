import argparse


def sid_alert(logFile):
    print('[*] Start parsing sid from json file')

    import json

    sAlert = []
    logs = open(logFile, "r").read().splitlines()
    for log in logs:
        try: sAlert.append(f"{json.loads(log)['alert']['signature_id']}")
        except: print(f'[-] {log}')

    print('[+] Finish parsing sid from json file\n')
    return list(set(sAlert))


def sid_all(sAlert):
    print('[*] Start parsing sid from base file for comparision')
    import os
    BASE_DIR = os.path.dirname(os.path.abspath(__file__)) + '/../rules/'

    for filename in ['full_ruleset.rules', 'include.rules']:
        if os.path.isfile(BASE_DIR + filename): rules = open(BASE_DIR + filename, 'r').read().splitlines()

    if 'rules' not in locals():
        print('[-] There is no file for comparision')
        exit(0)

    import re

    sid = re.compile(r'sid:\d{1,}')
    for rule in rules:
        if sid.findall(rule)[0][4:] in sAlert: filename = 'include.rules'
        else: filename = 'exclude.rules'
        open(BASE_DIR + filename, 'a').write(f'{rule}\n')

    print('[+] Finish parsing sid from base file and comparing\n')


def compare(args):
    sAlert = sid_alert(args.jsonFile)
    sid_all(sAlert)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("jsonFile", help='the target file to parse')
    args = parser.parse_args()

    compare(args)


if __name__ == "__main__":
    main()
