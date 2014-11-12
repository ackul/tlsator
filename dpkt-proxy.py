#!/usr/bin/env python
LISTEN_PORT = 8000
SERVER_PORT = 4431
SERVER_ADDR = "127.0.0.1"

from twisted.internet import protocol, reactor
from twisted.python import log
import sys


# Adapted from http://stackoverflow.com/a/15645169/221061
class ServerProtocol(protocol.Protocol):
    def __init__(self):
        self.buffer = None
        self.client = None

    def connectionMade(self):
        factory = protocol.ClientFactory()
        factory.protocol = ClientProtocol
        factory.server = self

        reactor.connectTCP(SERVER_ADDR, SERVER_PORT, factory)

    # Client => Proxy
    def dataReceived(self, data):
        print data
        if self.client:
            self.client.write(data)
        else:
            self.buffer = data

    # Proxy => Client
    def write(self, data):
        self.transport.write(data)


class ClientProtocol(protocol.Protocol):
    def connectionMade(self):
        self.factory.server.client = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''

    # Server => Proxy
    def dataReceived(self, data):
        self.factory.server.write(data)

    # Proxy => Server
    def write(self, data):
        if data:
            self.transport.write(data)



def main():
    factory = protocol.ServerFactory()
    factory.protocol = ServerProtocol

    reactor.listenTCP(LISTEN_PORT, factory)
    reactor.run()


if __name__ == '__main__':
    main()
