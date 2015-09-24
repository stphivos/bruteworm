#! /usr/bin/env python

from os import path
from itertools import product
from passlib.handlers.windows import lmhash, nthash


def generate_hashes(filename, alphabet, min_chars, max_chars, log=None):
    count = 0

    def hash_word(word):
        return '{0}:{1}'.format(lmhash.encrypt(word), nthash.encrypt(word))

    if filename:
        with open(filename) as f:
            for line in f:
                data = hash_word(line.strip())
                if log:
                    count += 1
                    log('# {0} -> {1}'.format(count, data))

                yield data
    else:
        for i in range(min_chars, max_chars + 1):
            for p in product(alphabet, repeat=i):
                data = hash_word(''.join(p))
                if log:
                    count += 1
                    log('# {0} -> {1}'.format(count, data))

                yield data


def generate_credentials(username, dictionary, alphabet, min_chars, max_chars, log=None):
    count = 0
    if dictionary:
        if not path.isfile(dictionary[1]):
            raise Exception('Dictionary file {0} does not exist.'.format(dictionary[1]))
        with open(dictionary[1]) as f:
            for line in f:
                password, hash_a, hash_b = '', '', ''

                if dictionary[0] == 'hash':
                    hash_a, hash_b = line.strip().split(':')
                elif dictionary[0] == 'pass':
                    password = line.strip()
                else:
                    raise Exception('Unknown type of dictionary file: {0}'.format(dictionary[0]))

                if log:
                    count += 1
                    log('# {0} -> {1} {2} {3}'.format(count, password, hash_a, hash_b))

                yield username, password, hash_a, hash_b
    else:
        for i in range(min_chars, max_chars + 1):
            for f in product(alphabet, repeat=i):
                if log:
                    count += 1
                    log('# {0} -> {1}'.format(count, ''.join(f)))

                yield username, ''.join(f), '', ''
