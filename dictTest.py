recordCount = 1

def main():
  d=dict()
  while(1):
    global recordCount
    key = raw_input("Enter key: ")
    if key in d:
      d[key].append(recordCount)
    else:
      d[key] = [recordCount]
    print d
    recordCount += 1



if __name__ == "__main__":
  main()
