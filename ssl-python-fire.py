'''
RTC Interceptor
Achin Kulshrestha - 3 March 2015
Inspired from Danmcinerney DNS spoofing project
'''
import nfqueue
from scapy.all import *
import os
import binascii
from random import randint
from collections import defaultdict
import logging
logger = logging.getLogger(__name__)
import logic
import sys
import getopt
import struct

lengthOfThisRecordLeft=0
count = 0
lower = 30
higher = lower+50
val = 0
d = defaultdict(list)
dropped = defaultdict(list)
lenDict = defaultdict(int)
record_count = 0
record_pending = False
record_pending_remaining_length=0
record_drop_list=''
ipLenToBeRemoved = 0
#Setting up iptables to enable queuing packets that match the rule
#os.system('sudo iptables -A INPUT -i eth0 -p udp -s 128.104.153.129 -j NFQUEUE') 

#os.system('sudo iptables -A INPUT -i eth0 -p udp -s 128.104.153.129 -m string --algo bm --to 30 --hex-string "|17 fe ff|" -j NFQUEUE') 

##TESTING HANGOUTS CHAT#####
#os.system('sudo iptables -A INPUT -i eth0 -p udp -s 172.16.1.162 -j NFQUEUE')
os.system('sudo iptables -A OUTPUT -p tcp -d 172.16.0.164 -j NFQUEUE')
#os.system('sudo iptables -A INPUT -i eth0 -p udp -s 74.125.192.127 -m string --algo bm --to 47 --hex-string "|00 01|" -j NFQUEUE') 

#Butter cream of the program, mangling is done here

##TESTING Facebook CHAT#####
##os.system('sudo iptables -A INPUT -i eth0 -p tcp --sport 443 -m string --algo bm --to 107 --hex-string "|17 03 03|" -j NFQUEUE') 

RECORD_TYPES = {
    20: "TLSChangeCipherSpec",
    21: "TLSAlert",
    22: "TLSHandshake",
    23: "TLSAppData",
}

def usage():
	sys.stdout.write("TLSator was created while having multiple Redbulls in the Blood Stream :)\n")
	sys.stdout.write("@arcaneak\n")
	sys.stdout.write("Usage: %s -h -a -r 1,2,3,4,5\n" % (sys.argv[0]))
	sys.stdout.write("-h|--help:\n")
	sys.stdout.write("-a|--analyze:\n")
	sys.stdout.write("-r|--recordnos: Comma seperated string of to-be canceled records\n")
	sys.stdout.write("To stop the proxy, press CTRL+C\n")
	sys.exit(2)


def recv_tls_record(tcpData):
	tls_header = tcpData[0:5]
	#print "TLS_HEADER-" +binascii.hexlify(tls_header)
	if not tls_header:
		print "Unexpected header"
		return None,None,None,None
	typ = tls_header[0:1]
	ver = tls_header[1:3]
	length = tls_header[3:5]
	return typ,ver,length

def awesomeFunction(tcpData):
	global record_count
	global record_pending
	global record_pending_remaining_length
	global record_drop_list
	if(record_pending == True):
		print "Continuing Segment of length %d: pending length is %d: " % (len(tcpData),record_pending_remaining_length)
		record_pending_remaining_length -= len(tcpData)
		if record_pending_remaining_length == 0:
			print "Record is no more pending..."
			record_pending = False
		elif record_pending_remaining_length <0:
			if(record_pending_remaining_length > -5):
				#alert situation,even header spans two packets
				#If I want to drop it drop it now, reduce ip len by the record pending length
				#else put the header part in a buffer and make sure to reference it in the next packet receive
				print "Things are gravely interesting, partial header in this packet of size %d: " % record_pending_remaining_length
				record_pending=False				
				return tcpData[:record_pending_remaining_length],(0-record_pending_remaining_length)
			print "Things are interesting: record found in this segment of length %d" % (0-record_pending_remaining_length)	
			start = len(tcpData) - (0-record_pending_remaining_length)			
			end=len(tcpData)
			#print "start %d and end %d" % (start,end)
			#print str(tcpData[start:end])
			while(start < end ):
				typ,ver,length = recv_tls_record(tcpData[start:end])
				#Drop logic comes here
				#if record_count == #what is input by the user
				length = int(binascii.hexlify(length),16)
				if not typ:
					print "Something went wrong"
				else:
					record_count+=1
					print 'Received Record: (%d) type: %s, Length: %d' %(record_count, RECORD_TYPES[int(binascii.hexlify(typ),16)],length)
					if str(record_count) in record_drop_list:
						logger.info("We have reached Record count - %d", record_count)
						decision = raw_input("do you want to cancel this record y/n?: ")
						if(decision == "y"):
							print "Packet Dropped..."
							return tcpData[:start],(end-start)

				if length > start + end:
					print "Unfinished record, it is going to continue..."
					record_pending = True
					record_pending_remaining_length = length + 5 - (start+end)
					print "Length remaining %d:\n " % record_pending_remaining_length
					break
				start += length+5
			return tcpData,0
	else:
		start = 0
		end = len(tcpData)
		while(start < end ):
			typ,ver,length = recv_tls_record(tcpData[start:end])
			#Drop logic comes here
			#if record_count == #what is input by the user
			length = int(binascii.hexlify(length),16)
			if not typ:
				print "Something went wrong"
			else:
				record_count+=1
				print 'Received Record: (%d) type: %s, Length: %d' %(record_count, RECORD_TYPES[int(binascii.hexlify(typ),16)],length)
				if str(record_count) in record_drop_list:
					logger.info("We have reached Record count - %d", record_count)
					decision = raw_input("do you want to cancel this record y/n?: ")
					if(decision == "y"):
						print "Packet Dropped..."
						return tcpData[:start],(end-start)
			if length > start + end:
				print "Unfinished record, it is going to continue..."
				record_pending = True
				record_pending_remaining_length = length + 5 - (start+end)
				print "Length remaining %d:\n " % record_pending_remaining_length
				break
			start += length+5		
	return tcpData,0
		
def callback(dummy,payload):
	global count
	global d
	global lower
	global higher
	global val
	global lenDict
	global record_count
	global record_pending
	global record_pending_remaining_length
	global ipLenToBeRemoved
	count +=1
	data = payload.get_data()
	pkt = IP(data)
	#Plug into TCP data, you can replace this with UDP
	tcpData=pkt[TCP].payload
	#if(len(tcpData)>0):
		
	#	print 'Data ' +binascii.hexlify(str(pkt[TCP].payload)) + 'length-' + str(len(tcpData))
	
	#Check if data has some length
	#If len(rawLoad >0) that means it is a ssl data and not just acks, syns etc
	'''
	if(len(tcpData)>0):
		ipLenToBeRemoved=0
		newData = logic.driver(tcpData)
		pkt[TCP].payload = newData
		if(ipLenToBeRemoved > 0):
			print "Changing IP len by %d " % ipLenToBeRemoved
			pkt[IP].len -= ipLenToBeRemoved
			
			#Changing checksum values
			del pkt[IP].chksum
			del pkt[TCP].chksum
	'''	
	tcpData = str(tcpData)	
	if(len(str(tcpData))>0):
		pkt.show()
		try:
			print "ipLenToBeRemoved %d: " % ipLenToBeRemoved
			if ipLenToBeRemoved == 3:
				print "came here"
				y = raw_input("fake enter: ")
			tcpData,ipLenToBeRemoved = awesomeFunction(tcpData)
			pkt[TCP].payload = tcpData
		except Exception as e:
			print "Exception in awesomeFunction %s" % str(e)
		if(ipLenToBeRemoved > 0):
			print "Time to mess with the packet: Changing IP len by %d " % ipLenToBeRemoved
			pkt[IP].len -= ipLenToBeRemoved
			del pkt[IP].chksum
			del pkt[TCP].chksum
		pkt.show()	
	#print("------------------------Begin Packet-%d--------------------------------" % count)	
	#print "Total Packet	Length - %d" % len(pkt)
	#print "Application data Length (RTP and RTP EVENT) - %d" % len(rawLoad)
	#print d
	#print lenDict
	#payload.set_verdict(nfqueue.NF_DROP)
	#print "Length Packet %d count %d" % (len(rawLoad),count)
	payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
	#print("--------------------------End Packet------------------------------------\n")

def main():
	global d	
	#Get an object to the queue
	q = nfqueue.queue()
	q.open()
	#Unbinding existing NF_queue handler for AF_INET
	q.unbind(socket.AF_INET)
	#Bind nfnetlink_queue as nf_queue handler for AF_INET
	q.bind(socket.AF_INET)
	#Set callback when a packet is received
	q.set_callback(callback)

	#Name says it all
	q.create_queue(0)
	try:
		q.try_run()
	except KeyboardInterrupt:
		print "Exiting..."
		q.unbind(socket.AF_INET)
		q.close()
		os.system('sudo iptables -F')
		os.system('sudo pkill -9 python')


if __name__ == '__main__':
	try:
		opts, args = getopt.getopt(sys.argv[1:], "halr:v", ["help", "analyze","log","recordnos="])
	except getopt.GetoptError as err:
		print str(err)
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
	if(len(recordnos)>0):
		record_drop_list = recordnos.split(',')
		#record_drop_list = [int(i) for i in record_drop_list]
		#print "I will stop the record flow at %s" % ",".join(str(j) for j in recordnosList)
		#logger.info("I will stop the record flow at %s", ",".join(str(j) for j in recordnosList))
	import logging.config
	if(logToFile):
		logging.basicConfig(format='%(levelname)s:%(asctime)s:%(message)s',filename='tlsator.log',filemode='w', level=logLevel)
	else:
		#logging.basicConfig(format='%(levelname)s:%(asctime)s:%(message)s', level=logLevel)
		logging.basicConfig(format='%(levelname)s:%(message)s', level=logLevel)
	main()
