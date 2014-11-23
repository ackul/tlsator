import logging
logger = logging.getLogger(__name__)
import sys
import getopt


analyze = False
recordnosList = []

def usage():
  sys.stdout.write("Usage: %s -h -a -r 1,2,3,4,5\n" % (sys.argv[0]))
  sys.stdout.write("-h|--help:\n")
  sys.stdout.write("-a|--analyze: Perform the analysis run\n")
  sys.stdout.write("-r|--recordnos: Comma seperated string of to-be canceled records\n")
  sys.stdout.write("To stop the proxy, press CTRL+C\n")
  sys.exit(2)

def main():
  import tlsatorv2
  tlsatorv2.do()

if __name__ == '__main__':
  import logging.config
  try:
    opts, args = getopt.getopt(sys.argv[1:], "har:v", ["help", "analyze","recordnos="])
  except getopt.GetoptError as err:
    #print help information and exit:
    print str(err) # will print something like "option -a not recognized"
    usage()
    sys.exit(2)
  recordnos = ''
  verbose = False
  logLevel = logging.DEBUG
  for o, a in opts:
    if o == "-v":
      logLevel = logging.DEBUG
    elif o in ("-h","--help"):
      usage()
      sys.exit(2)
    elif o in ("-a","--analyze"):
      analyze = True
    elif o in ("-r","--recordnos"):
      recordnos = a
    else:
      assert false, "unhandled option"

  if(len(recordnos)):
    recordnosList = recordnos.split(',')
    print recordnosList
  
  logging.basicConfig(format='%(levelname)s:%(asctime)s:%(message)s',filename='tlsator.log',filemode='w', level=logLevel)
  main()
