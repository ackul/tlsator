#!/usr/bin/env python
LISTEN_PORT = 443
SERVER_PORT = 443
SERVER_ADDR = "64.233.183.102"
import dpkt
from twisted.internet import protocol, reactor
from twisted.python import log
import sys
from collections import defaultdict

DEBUG = False

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
        print "Received data from Client"
        '''var = raw_input("Do you want to Drop this: ")
        if(var=="y"):
          data=""
        else:'''
        makeDecision(data)
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
        print "Received data from Server"
        '''var = raw_input("Do you want to Drop this: ")
        if(var=="y"):
          data=""
        else:'''
        makeDecision(data)
        self.factory.server.write(data)

    # Proxy => Server
    def write(self, data):
        if data:
            self.transport.write(data)

def handleTLSHandshake(record):
  print "Handshake Packet"

def handleTLSAlert(record):
  print "ALERT Packet"
  if len(record.data) == 0:
      print ""

  try:
      alert = dpkt.ssl.TLSAlert(record.data)
      #print handshake
  except dpkt.dpkt.NeedData, e:
      # TODO: shouldn't happen in practice for handshakes... but could. meh.
      print e


def handleTLSAppData(record):
  print "Application Data"

def handleTLSChangeCipherSpec(record):
  print "change Cipher Spec"


def makeDecision(data):

  counters = defaultdict(int)
  DROP = 0
  records = []
  print "Length of the Data %s" % len(data)
  try:
      records, bytes_used = dpkt.ssl.TLSMultiFactory(data)
      print "Bytes_Parsed %s " % bytes_used
  except dpkt.ssl.SSL3Exception, e:
    print e

  if len(records) <= 0:
    print "Didn't find Record"
  else:
    print "Number of SSL Records - %s"% len(records)
    for record in records:
        # TLS handshake only
        if record.type == 22:

            handleTLSHandshake(record)
        elif record.type== 21:
            handleTLSAlert(record)
        elif record.type == 20:
            handleTLSChangeCipherSpec(record)
        elif record.type == 23:
            handleTLSAppData(record)

def main():
    factory = protocol.ServerFactory()
    factory.protocol = ServerProtocol

    reactor.listenTCP(LISTEN_PORT, factory)
    reactor.run()


if __name__ == '__main__':
    main()
