import dpkt
import binascii
import struct
incRecordBuffer = b''
incRecordBufferStruct = ''
dataOffsetInTheNextPacket = 0
incRecordBufferDrop = 0
#need to
#structure which would have length, type etc

def displayAndKeepRecord(record):
  print record.type
  return 1

def driver(data):
  global incRecordBuffer
  global incRecordBufferStruct
  global dataOffsetInTheNextPacket
  global incRecordBufferDrop
  #This is the TCP data recevied from the server
  dataLen = len(data)
  #Since we have completed handshake, this should be a SSL packet hoping :P
  #To keep track of where we are right now...not sure if really needed
  bytes_left = len(data)
  startPosition = 0
  packet = b''
  #if the drop flag was true I just set the start position and future code would take care
  #else I add the the extra data correspodning to the packet as it is
  print "dataOffsetInTheNextPacket %d" % dataOffsetInTheNextPacket
  if(len(data) < dataOffsetInTheNextPacket):
    dataOffsetInTheNextPacket -= len(data)
    if(incRecordBufferDrop == 1):
      return packet
    else:
      return data

  if(len(incRecordBuffer)):
    if(incRecordBufferDrop == 1):
      startPosition = dataOffsetInTheNextPacket
    else:
      startPosition = dataOffsetInTheNextPacket
      packet += data[0:dataOffsetInTheNextPacket]
    dataOffsetInTheNextPacket = 0
    incRecordBuffer = b''
    incRecordBufferDrop = 0
    incRecordBufferStruct = ''

  i = startPosition

  bytes_left = len(data) - i;
  #DEBUG


  recordArr = []
  while (bytes_left > 0):
    try:
      print "****Starting to Parse Record****"

      record,bytes_parsed,incFlag,incRecLength = dpkt.ssl.TLSMultiFactoryAK(data[i:])
      #print record.type
      print "packet %s" % binascii.hexlify(packet)
      print "Bytes left %s" % bytes_left
      print "Start Position %d" % i

      print "Bytes Parsed %d" % bytes_parsed
      print "incFlag %d" % incFlag
      print "incRecLength %d" % incRecLength



      #If the record was incomplete, then we store the data in a different buffer and remember that when the next packet arrives
      if(incFlag):
        dataOffsetInTheNextPacket = incRecLength + 5 - bytes_left
        #Storing the record bytes in a global buf so as to remember it next tym and then show the user
        incRecordBuffer = data[i:]
        #incRecordBufferStruct = record
        #Iam breaking because it doesn't make sense to do anything funny
        break
      elif (len(record)):
        #This takes care of the situation where the packet has a complete record
        recordArr.append(record)
        print "Record Appended"
        print "Record Len %d" % len(record)
        bytes_left = bytes_left - bytes_parsed
        i += len(record)
    except Exception as e:
      print e

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
      print len(packet)
      print "packet %s" % binascii.hexlify(packet)
    else:
      continue
  if(len(incRecordBuffer)):
    #show record info to the user
    print "This is an Incomplete Record"
    if(displayAndKeepRecord(record)):
      pack_format = ">BHH"
      if(len(incRecordBuffer)):
        try:
          print "inRecordBuf %s" % binascii.hexlify(incRecordBuffer)
          pack_format += "%ss" % len(incRecordBuffer)
          print "packet %s" % binascii.hexlify(packet)
          print "The record Type"
          print record.type
          print "The record version"
          print record.version
          print "The record length"
          print record.length
          packet += struct.pack(pack_format,record.type,record.version,record.length,incRecordBuffer)
          print len(packet)
          print "packet %s" % binascii.hexlify(packet)
        except Exception as e:
          print e
    else:
      incRecordBufferDrop = 1

  return packet

incRecordBuffer = b''
incRecordBufferStruct = ''
dataOffsetInTheNextPacket = 0
incRecordBufferDrop = 0
#need to initialize
