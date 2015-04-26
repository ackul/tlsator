#!/usr/bin/env python
LISTEN_PORT = 8077
SERVER_PORT = 8070
SERVER_ADDR = '172.16.3.14'
import dpkt
from twisted.internet import protocol, reactor
from twisted.python import log
import logging
logger = logging.getLogger(__name__)
import sys
import logic
import getopt
from collections import defaultdict
import binascii
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
        logger.debug("Received packet from the client")
        '''var = raw_input("Do you want to Drop this: ")
        if(var=="y"):
          data=""
        else:'''
        logger.info("Packet Received: Client -> Server")
        data = logic.driver(data)
        if self.client:
            self.client.write(data)
        else:
            self.buffer = data

    # Proxy => Client
    def write(self, data):
        self.transport.write(data)

    def connectionLost(self,reason):
      self.transport.loseConnection()

class ClientProtocol(protocol.Protocol):
    def connectionMade(self):
        self.factory.server.client = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''

    # Server => Proxy
    def dataReceived(self, data):
      logger.info("Packet Received: Server -> Client")
      #data = logic.driver(data)
      #print "Writing new data"
      self.factory.server.write(data)

    # Proxy => Server
    def write(self, data):
        if data:
            self.transport.write(data)

    def connectionLost(self,reason):
      logger.debug("Closed connection")
      self.transport.loseConnection()

def usage():
  sys.stdout.write("TLSator was created while having multiple Redbulls in the Blood Stream :)\n")
  sys.stdout.write("@arcaneak\n")
  sys.stdout.write("Usage: %s -h -a -r 1,2,3,4,5\n" % (sys.argv[0]))
  sys.stdout.write("-h|--help:\n")
  sys.stdout.write("-a|--analyze:\n")
  sys.stdout.write("-r|--recordnos: Comma seperated string of to-be canceled records\n")
  sys.stdout.write("To stop the proxy, press CTRL+C\n")
  sys.exit(2)



def main():
    factory = protocol.ServerFactory()
    factory.protocol = ServerProtocol

    reactor.listenTCP(LISTEN_PORT, factory)
    reactor.run()


if __name__ == '__main__':
    try:
      opts, args = getopt.getopt(sys.argv[1:], "halr:v", ["help", "analyze","log","recordnos="])
    except getopt.GetoptError as err:
      #print help information and exit:
      print str(err) # will print something like "option -a not recognized"
      usage()
      sys.exit(2)
    recordnos = ''
    verbose = False
    logLevel = logging.INFO
    logToConsole = True
    logToFile = False
    for o, a in opts:
      if o == "-v":
        logLevel = logging.DEBUG
      elif o in ("-h","--help"):
        usage()
        sys.exit(2)
      elif o in ("-a","--analyze"):
        logic.analyze = True
      elif o in ("-r","--recordnos"):
        recordnos = a
      elif o in ("-l","--log"):
        logToFile = True
        logToConsole = False
      else:
        assert false, "unhandled option"

    if(len(recordnos)):
      recordnosList = recordnos.split(',')
      logic.recordnosList = [int(i) for i in recordnosList]
      logger.info("I will stop the record flow at %s", logic.recordnosList)

    import logging.config
    if(logToFile):
      logging.basicConfig(format='%(levelname)s:%(asctime)s:%(message)s',filename='tlsator.log',filemode='w', level=logLevel)
    else:
      logging.basicConfig(format='%(levelname)s:%(asctime)s:%(message)s', level=logLevel)
    main()
