import getopt, sys

def usage():
  sys.stdout.write("Usage: %s -h -r 1,2,3,4,5\n" % (sys.argv[0]))
  sys.stdout.write("-h|--help: Show this message\n")
  sys.stdout.write("-r|--recordnos: Comma seperated string of to-be removed records\n")
  sys.stdout.write("To stop the proxy, press CTRL+C\n")
  sys.exit(2)

def main():
  try:
    opts, args = getopt.getopt(sys.argv[1:], "hr:v", ["help", "recordnos="])
  except getopt.GetoptError as err:
    #print help information and exit:
    print str(err) # will print something like "option -a not recognized"
    usage()
    sys.exit(2)
  recordnos = ''
  verbose = False
  logLevel = 1
  for o, a in opts:
    if o == "-v":
      logLevel = 0
    elif o in ("-h","--help"):
      usage()
      sys.exit()
    elif o in ("-r","--recordnos"):
      recordnos = a
    else:
      assert false, "unhandled option"

  if(len(recordnos)):
    global recordnosList = recordnos.split(',')
    print recordnosList
  else:
    usage()
    sys.exit(0)


if __name__ == "__main__":
  main()
