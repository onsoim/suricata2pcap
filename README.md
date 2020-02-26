
# suricata2pcap(suricata rule -> pcap)

## s2p.py

```bash
usage: s2p.py [-h] config rules

positional arguments:
  config      Suricata config file
  rules       Suricata rule file

optional arguments:
  -h, --help  show this help message and exit
```

## util/compare.py

```bash
usage: compare.py [-h] [-o SID_FILE] json_file

positional arguments:
  json_file             the target file(json) to parse sid

optional arguments:
  -h, --help            show this help message and exit
  -o SID_FILE, --output SID_FILE
                        Drop list of SIDs as a file
```

- Input
  - a part of eve file (json log file)
- Output
  - pcaps that were included in input json log
- Options
  - Drop list of sids from given Input as a
