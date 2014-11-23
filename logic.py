import dpkt
import binascii
import struct
import sys
incRecordBuffer = b''
incRecordBufferStruct = ''
dataOffsetInTheNextPacket = 0
incRecordBufferDrop = 0
recordCount = 0
import logging
logger = logging.getLogger(__name__)
d=dict()
analyze = False
recordnosList = []

#need to
#structure which would have length, type etc

class incStruct():
  def __init__(self,rectype,recversion,reclength):
    self.type = rectype
    self.version = recversion
    self.length = reclength

def displayRecord(record):
  if record.type == 22:
    logger.info("TLS Handshake Record")
  elif record.type== 21:
    logger.info("TLS Alert Record")
  elif record.type == 20:
    logger.info("TLS ChangeCipherSpec")
  elif record.type == 23:
    logger.info("TLS Application Data")
  logger.debug('Received Record: \nRecord Type-%d\nRecord Length-%d\n',record.type,record.length)

def keepRecord(record, count):
  global recordnosList
  #print count
  #print len(recordnosList)
  if(len(recordnosList)):
    if count in recordnosList:
      logger.info("We have reached Record count - %d", count)
      decision = raw_input("do you want to cancel this record y/n?: ")
      if(decision == "y"):
        print "Returning 0"
        return 0
  return 1

RECORD_TYPE = {
    20: 'TLSChangeCipherSpec',
    21: 'TLSAlert',
    22: 'TLSHandshake',
    23: 'TLSAppData',
}

def printDictionary(d):
  logger.info("Record Stats are as follows:")
  for key in d:
    print RECORD_TYPE[key]
    logger.debug("%s",RECORD_TYPE[key])
    for val in d[key]:
      sys.stdout.write('('+str(val)+')')
    sys.stdout.write('\n')
  logger.debug("Now the alert record would be handled")


def displayAndKeepRecord(record, count):
  displayRecord(record)
  return keepRecord(record, count)

def driver(data):

  logger.info('Driver-SSL data of length %d',len(data))
  global incRecordBuffer
  global incRecordBufferStruct
  global dataOffsetInTheNextPacket
  global incRecordBufferDrop
  global recordCount
  global d
  global analyze
  #This is the TCP data recevied from the server
  dataLen = len(data)
  #Since we have completed handshake, this should be a SSL packet hoping :P
  #To keep track of where we are right now...not sure if really needed
  bytes_left = len(data)
  startPosition = 0
  packet = b''
  #if the drop flag was true I just set the start position and future code would take care
  #else I add the the extra data correspodning to the packet as it is

  logger.debug('Driver- dataOffsetInTheNextPacket %d',dataOffsetInTheNextPacket)
  logger.debug('data received %s', binascii.hexlify(data[0:(dataOffsetInTheNextPacket+5)]))
  #This code handles the case where the previous record is still not fulfilled by the upcoming packets
  if(dataOffsetInTheNextPacket > 0):
    if(len(data) < dataOffsetInTheNextPacket):
      logger.debug('Pending Record - SSL data less than dataOffsetInTheNextPacket, If drop flag true, return empty Packet')
      dataOffsetInTheNextPacket -= len(data)
      logger.debug('Pending Record - New dataOffsetInTheNextPacket %d',dataOffsetInTheNextPacket)
      if(incRecordBufferDrop == 1):
        logger.debug('Pending Record - Drop flag is 1, returning empty data')
        return packet
      else:
        logger.debug('Pending Record - Drop flag is 0, returning data')
        return data
    else:
      logger.debug('Pending Record - Incomplete record completes in this packet')

    if(len(incRecordBuffer)):
      logger.debug('Record Buffer Adjust - Packet with incomplete Record')
      if(incRecordBufferDrop == 1):
        logger.debug('Record Buffer Adjust - Drop Flag is 1')
        startPosition = dataOffsetInTheNextPacket
      else:
        startPosition = dataOffsetInTheNextPacket
        packet += data[0:dataOffsetInTheNextPacket]
      dataOffsetInTheNextPacket = 0
      incRecordBuffer = b''
      incRecordBufferDrop = 0
      incRecordBufferStruct = ''
    else:
      logger.warning('Record Buffer Adjust - dataOffsetInTheNextPacket > 0 but no buffer in incRecordBuffer ')

  i = startPosition

  bytes_left = len(data) - i;
  #DEBUG

  oldRecordCount = recordCount
  recordArr = []
  while (bytes_left > 0):
    try:
      logger.debug('****Starting to Parse the record****')
      logger.debug('Before Multifactory - bytes left %s',bytes_left)
      record,bytes_parsed,incFlag,incRecLength = dpkt.ssl.TLSMultiFactoryAK(data[i:])
      recordCount += 1

      key = record.type
      if key in d:
        d[key].append(recordCount)
      else:
        d[key] = [recordCount]
      if (key == 21 and analyze):
        printDictionary(d)

      #print record.type
      logger.debug('Multifactory Output: \nStart Position-%d\nbytes parsed -%d\nincFlag-%d\nincRecLength-%d\nRecord Count-%d', i, bytes_parsed,incFlag,incRecLength,recordCount)

      #If the record was incomplete, then we store the data in a different buffer and remember that when the next packet arrives
      if(incFlag):
        logger.debug('incFlag 1: populating structures')
        logger.debug('dataOffsetInTheNextPacket old Value %d',dataOffsetInTheNextPacket)
        dataOffsetInTheNextPacket = incRecLength + 5 - bytes_left
        logger.debug('dataOffsetInTheNextPacket new Value %d',dataOffsetInTheNextPacket)
        #Storing the record bytes in a global buf so as to remember it next tym and then show the user
        incRecordBuffer = data[i:]
        incRecordBufferStruct = incStruct(record.type,record.version,record.length)
        #Iam breaking because it doesn't make sense to do anything funny
        break
      elif (len(record)):
        #This takes care of the situation where the packet has a complete record

        recordArr.append(record)
        logger.debug('Appended RecordArr: length of recordArr-%d', len(recordArr))
        bytes_left = bytes_left - bytes_parsed
        i += len(record)
    except Exception as e:
      logger.debug('Exception: %s', e)

  #Now we have the record Buffer, lets display that to the user and make decision
  logger.debug('Got %d Full Records in this packet',len(recordArr))
  #this is to get the value of record count
  '''print "Record Nums----"
  print "record Count"
  print recordCount
  print "Old Record Count"
  print oldRecordCount
  print "Len RecordARR"
  print len(recordArr)
  print "---EndNums"
  '''
  if((recordCount - oldRecordCount) > len(recordArr)):
    p = recordCount - len(recordArr)
  else:
    p = recordCount - len(recordArr) + 1
  for record in recordArr:
    if(displayAndKeepRecord(record,p)):
      #print len(record.data)
      #print record.type
      #+str(record.version)+str(record.length)+str(record.data)
      pack_format = "!BHH"
      if(len(record.data)):
        pack_format += "%ss" % len(record.data)
      packet += struct.pack(pack_format,record.type,record.version,record.length,record.data)
      logger.debug('Normal Record Packet Construction: Packet Length %d', len(packet))
    else:
      p += 1
      continue
    p += 1
  if(len(incRecordBuffer)):
    #show record info to the user
    logger.debug('Received Record: \nRecord Type-%d\nRecord Length-%d\n',record.type,record.length)
    if(displayAndKeepRecord(record,recordCount)):
      if(len(incRecordBuffer)):
        try:
          packet += incRecordBuffer
          #print len(packet)
          #print "packet %s" % binascii.hexlify(packet)
        except Exception as e:
          print e
    else:
      incRecordBufferDrop = 1
  logger.info()
  return packet
