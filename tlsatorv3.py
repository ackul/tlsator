#!/usr/bin/env python
LISTEN_PORT = 443
SERVER_PORT = 4433
SERVER_ADDR = "128.105.175.15"
import dpkt
from twisted.internet import protocol, reactor
from twisted.python import log
import logging
logger = logging.getLogger(__name__)
import sys
import logic
from collections import defaultdict
import binascii
DEBUG = False
from twisted.internet import defer
from twisted.internet import protocol

class ProxyClientProtocol(protocol.Protocol):
    def connectionMade(self):
        logger.debug("Client: connected to peer")
        self.cli_queue = self.factory.cli_queue
        self.cli_queue.get().addCallback(self.serverDataReceived)

    def serverDataReceived(self, chunk):
        if chunk is False:
            self.cli_queue = None
            logger.debug("Client: disconnecting from peer")
            self.factory.continueTrying = False
            self.transport.loseConnection()
        elif self.cli_queue:
            logger.debug("Client: writing %d bytes to peer" % len(chunk))
            self.transport.write(chunk)
            self.cli_queue.get().addCallback(self.serverDataReceived)
        else:
            self.factory.cli_queue.put(chunk)

    def dataReceived(self, chunk):
        logger.debug("Client: %d bytes received from peer" % len(chunk))
        self.factory.srv_queue.put(chunk)

    def connectionLost(self, why):
        if self.cli_queue:
            self.cli_queue = None
            logger.debug("Client: peer disconnected unexpectedly")


class ProxyClientFactory(protocol.ReconnectingClientFactory):
    maxDelay = 10
    continueTrying = True
    protocol = ProxyClientProtocol

    def __init__(self, srv_queue, cli_queue):
        self.srv_queue = srv_queue
        self.cli_queue = cli_queue

class ProxyServer(protocol.Protocol):
    def connectionMade(self):
        self.srv_queue = defer.DeferredQueue()
        self.cli_queue = defer.DeferredQueue()
        self.srv_queue.get().addCallback(self.clientDataReceived)

        factory = ProxyClientFactory(self.srv_queue, self.cli_queue)
        reactor.connectTCP(SERVER_ADDR, SERVER_PORT, factory)

    def clientDataReceived(self, chunk):
        chunk = logic.driver(chunk)
        logger.debug("Server: writing %d bytes to original client" % len(chunk))
        self.transport.write(chunk)
        self.srv_queue.get().addCallback(self.clientDataReceived)

    def dataReceived(self, chunk):
        logger.debug("Server: %d bytes received" % len(chunk))
        self.cli_queue.put(chunk)

    def connectionLost(self, why):
        self.cli_queue.put(False)

def main():
    factory = protocol.Factory()
    factory.protocol = ProxyServer
    reactor.listenTCP(LISTEN_PORT, factory)
    reactor.run()

if __name__ == '__main__':
    import logging.config
    logging.basicConfig(format='%(levelname)s:%(asctime)s:%(message)s',filename='tlsator.log',filemode='w', level=logging.DEBUG)
    main()
