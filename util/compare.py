import argparse
import os


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


def gathering(sAlert):
    for sid in sAlert:
        try: os.rename(f'pcaps/{sid}.pcap', f'include/{sid}.pcap')
        except: pass


def compare(args):
    sAlert = sid_alert(args.json_file)
    if (args.sid_file):
        with open(args.sid_file, 'w') as w:
            w.write('\n'.join(sAlert))
    # sid_all(sAlert)
    gathering(sAlert)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(dest="json_file", help='the target file(json) to parse sid')
    parser.add_argument("-o", "--output", dest='sid_file', help="Drop list of SIDs as a file")
    args = parser.parse_args()

    compare(args)


if __name__ == "__main__":
    main()
