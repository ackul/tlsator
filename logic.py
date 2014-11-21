import dpkt
import binascii
import struct
incRecordBuffer = b''
incRecordBufferStruct = ''
dataOffsetInTheNextPacket = 0
incRecordBufferDrop = 0
recordCount = 0
import logging
logger = logging.getLogger(__name__)
#need to
#structure which would have length, type etc

class incStruct():
  def __init__(self,rectype,recversion,reclength):
    self.type = rectype
    self.version = recversion
    self.length = reclength

def displayAndKeepRecord(record):
  return 1

def driver(data):
  logger.info('Driver-SSL data of length %d',len(data))
  global incRecordBuffer
  global incRecordBufferStruct
  global dataOffsetInTheNextPacket
  global incRecordBufferDrop
  global recordCount
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
      logger.info('Pending Record - Incomplete record completes in this packet')

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


  recordArr = []
  while (bytes_left > 0):
    try:
      logger.debug('****Starting to Parse the record****')
      logger.debug('Before Multifactory - bytes left %s',bytes_left)
      record,bytes_parsed,incFlag,incRecLength = dpkt.ssl.TLSMultiFactoryAK(data[i:])
      recordCount += 1
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

  for record in recordArr:
    if(displayAndKeepRecord(record)):
      #print len(record.data)
      #print record.type
      #+str(record.version)+str(record.length)+str(record.data)
      pack_format = "!BHH"
      if(len(record.data)):
        pack_format += "%ss" % len(record.data)
      packet += struct.pack(pack_format,record.type,record.version,record.length,record.data)
      logger.debug('Normal Record Packet Construction: Packet Length %d', len(packet))
    else:
      continue
  if(len(incRecordBuffer)):
    #show record info to the user
    logger.debug('Incomplete Record: \nRecord Type-%s\nRecord version-%s\nRecord Length-%s\n',binascii.hexlify(str(incRecordBufferStruct.type)),binascii.hexlify(str(incRecordBufferStruct.version)),binascii.hexlify(str(incRecordBufferStruct.length)))
    if(displayAndKeepRecord(record)):
      if(len(incRecordBuffer)):
        try:
          packet += incRecordBuffer
          #print len(packet)
          #print "packet %s" % binascii.hexlify(packet)
        except Exception as e:
          print e
    else:
      incRecordBufferDrop = 1

  return packet
