import socket
from datetime import datetime
import os
import time
import threading
import requests
import uuid
import struct
import re
import subprocess

first = 1
ptotal = 0
btotal = 0
local = 0
noGeo = 0
f = 0
overwrite = "y"
ip = 0
lock = threading.Lock() #Makes all those above variables work with threading

#There was a bug where os.system would clear things infront of it in title(), the sleep line seems to fix it
#This only happens with the web hosted terminal I was using though
def title():
  os.system('cls' if os.name == 'nt' else 'clear')
  time.sleep(0.1)
  print ("\033[34m")
  print("███████████████████████████████████████████████████████████")
  print("█▄─▄█▄─▄▄─███─▄▄▄▄█─▄▄▄─██▀▄─██▄─▀█▄─▄█▄─▀█▄─▄█▄─▄▄─█▄─▄▄▀█")
  print("██─███─▄▄▄███▄▄▄▄─█─███▀██─▀─███─█▄▀─███─█▄▀─███─▄█▀██─▄─▄█")
  print("▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀")
  print ("\033[0m")

title()

print ("This tool gives info about entered IPs like DNS, ISP, and open ports with their banners.\n")
print ("Do you want to use a stealth scan?")
print ("Steath scans allow you to scan for open ports, but don't give as much info about found ports.")
print ("This is helpful if the IP you want to scan is blocking you with this setting off.")
stealth = input("\nStealth Scan? (Y/N)")
while stealth.lower() not in ["y", "yes", "n", "no"]:
  print("\nCan't recognise an answer, please input correctly.")
  stealth = input("Stealth Scan? (Y/N)")

title()

print ("Would you like to create a text file giving a summary on the scan results")
print ("This is helpful for archiving results and if you need to run this code multiple times.")
summary = input("\nCreate File? (Y/N)")
while summary.lower() not in ["y", "yes", "n", "no"]:
  print("\nCan't recognise an answer, please input correctly.")
  summary = input("Create File? (Y/N)")

title()

print("Info:\nThis scanner uses IPv4, if you're not sure if you have a v4 or v6 IP, then it's probably a v4.")
print("The intended purpose is for education and to be used with personally owned IPs.")
print("Unauthorised use of this tool on someone elses IP is not condoned and is your responsibility.")
print ("Domain names will also work and will give you its IP if you do enter one.")
if stealth.lower() in ["n" or "no"]:
  print("Some IPs may block this tool with stealth scan off, if you're not getting many ports with it off, try one with it on.")
print ("(ctrl+c won't work because of multi threading, just wait for it to finish)")

target = input(str("\n\n\033[32mIP/Domain To Scan:\033[0m"))
target = target.lower()

if target == "" or target == "127.0.0.1" or target == "localhost":
  local = 1

if summary.lower() in ["y", "yes"]:
  if f"{target} Scan Results.txt" in os.listdir():
    print (f"\nThere is already a file made for {target}, would you like to overwrite it?")
    overwrite = input("Overwrite File? (Y/N)")
    while overwrite.lower() not in ["y", "yes", "n", "no"]:
      print("\nCan't recognise an answer, please input correctly.")
      overwrite = input("Overwrite File? (Y/N)")
    if overwrite.lower() in ["y", "yes"]:
      with open (f"{target} Scan Results.txt", "w"):
        pass

title()

if summary.lower() in ["y", "yes"]:
  f = open(f"{target} Scan Results.txt", "a")
  if overwrite.lower() in ["n", "no"]:
    f.write ("\nDuplicate Scan:\n\n")

if target.count(".") != 3: #Checks if it's not an ip
  ip = socket.gethostbyname(target)
else:
  ip = 0

def infoGrab(target,local,f,summary,ip):
  
  if local == 1:
    print ("\n\033[35m- Scan Start -\033[0m")
    print (f"Time Of Scan: {str(datetime.now().replace(microsecond=0))}")
    print ("\nScanning Local Host Ports\n")
  
  else:
    print ("\n\033[35m- Scan Start -\033[0m")
    print (f"Time Of Scan: {str(datetime.now().replace(microsecond=0))}")
  
    print (f"Scanning \033[34m{target}\033[0m")
    if target.count(".") != 3: #Checks if it's not an ip
      print (f"IP: \033[34m{ip}\033[0m")
      if summary.lower() in ["y", "yes"]:
        f.write (f"IP: {ip}\n\n")
    else:
      ip = 0
      
  
    print (f"\nAttempting Reverse DNS Lookup")
    try:
      dns = socket.gethostbyaddr(target)[0] #Makes a request to the IP for a DNS
      print (f"\033[32mDNS Found: {dns}\033[0m\n")
      if summary.lower() in ["y", "yes"]:
        f.write (f"DNS: {dns}\n\n")
    except:
      print ("\033[31mCouldn't Find DNS\033[0m\n")
    
    print ("Searching For ISP")
    if ip == 0:
      url = (f"https://ipinfo.io/{target}/json") #Option for raw IPs
    else:
      url = (f"https://ipinfo.io/{ip}/json") #Option for websites
    try:
      respond = requests.get(url)
      isp = respond.json() #Converts json into something readable by python
      if "org" in isp:
        print (f"\033[32mISP Found: {isp['org']}\033[0m")
        if summary.lower() in ["y", "yes"]:
          f.write (f"ISP: {isp['org']}\n\n")
      elif "bogon" in isp:
        print ("\033[31mIP Entered Is Private\033[0m")
      else:
        print ("\033[31mNo ISP Found\033[0m")
    except:
      print ("\033[31mCouldn't Check For ISP\033[0m")
      
    print ("\nSearching For Server Geolocation")
    try:
      respond = requests.get(url) #Uses the same site as for ISP
      if "bogon" in isp:
        print ("\033[31mIP Entered Is Private\033[0m")
      geolocation = respond.json() #Converts JSON into something readable by Python
      if "country" in geolocation:
        print(f"\033[32mCountry: {geolocation['country']}\033[0m")
        if summary.lower() in ["y", "yes"]:
          f.write (f"Country Of Server: {geolocation['country']}\n")
      else:
        noGeo = 1
        if "bogon" not in isp:
          print (f"\033[31mCan't Find Geolocation\033[0m")
      if "city" in geolocation:
        print(f"\033[32mCity: {geolocation['city']}\033[0m")
        if summary.lower() in ["y", "yes"]:
          f.write (f"City Of Server: {geolocation['city']}\n")
      elif noGeo == 0:
        print("\033[31mCity information not found\033[0m")
        noGeo = 1
      if "region" in geolocation:
        print(f"\033[32mRegion: {geolocation['region']}\033[0m")
        if summary.lower() in ["y", "yes"]:
          f.write (f"Region Of Server: {geolocation['region']}\n\n")
      elif noGeo == 0:
        print("\033[31mRegion information not found\033[0m")
        noGeo = 1
    except:
      if "bogon" not in isp:
        print ("\033[31mCouldn't Check For Geolocation\033[0m")
        
    print ("\nRetrieving MAC Address From Network Interface")
    try:
      mac =':'.join(f'{(uuid.getnode() >> i) & 0xff:02x}' for i in range(0, 48, 8))
      if mac:
        print (f"\033[32mMAC Address Found: {mac}\033[0m")
        if summary.lower() in ["y", "yes"]:
            f.write (f"MAC Address: {mac}\n\n")
      else:
        print (f"\033[31mCouldn't Find MAC Address\033[0m")
    except:
      print (f"\033[31mCouldn't Contact Network Interface\033[0m") #Probably means the IP is down
  
def whoisServer(target,ip):
  #Uses a list to be more efficient than a ton of elif statements
  if target.count(".") != 3: #Checks if it's not an ip
    ip = socket.gethostbyname(target)
  else:
    ip = 0
  if ip != 0:
    whoisServers = {
      ".com": "whois.verisign-grs.com",
      ".net": "whois.verisign-grs.com",
      ".org": "whois.pir.org",
      ".info": "whois.afilias.net",
      ".biz": "whois.nic.biz",
      ".name": "whois.nic.name",
      ".pro": "whois.registrypro.pro",
      ".mobi": "whois.dotmobiregistry.net",
      ".asia": "whois.nic.asia",
      ".us": "whois.nic.us",
      ".uk": "whois.nic.uk",
      ".ca": "whois.cira.ca",
      ".au": "whois.auda.org.au",
      ".de": "whois.denic.de",
      ".fr": "whois.nic.fr",
      ".in": "whois.registry.in",
      ".jp": "whois.jprs.jp",
      ".cn": "whois.cnnic.cn",
      ".br": "whois.registro.br",
      ".ru": "whois.tcinet.ru"
    }
    for tld, server in whoisServers.items():
      if re.search(rf"{tld}$", target):  # Match TLDs properly
        return server
    #Don't need an else because you're using return
    return "No Result"
  else:
    return ("NIP")


  
def whoisLookup(target,server):
  try:
    #Connects to the port used for lookups
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((server, 43))
    
    #Sends the domain to the port as bytes
    query = target + "\r\n"
    sock.sendall(query.encode())
    #Recieves the response as bytes
    response = b""
    while True: #Repeats until a response is given
      data = sock.recv(4000)
      if not data:
        break
      response += data
    sock.close()
    return response.decode()
  except socket.timeout:
    print("\033[31mTimeout While Recieving Data\033[0m")
  except Exception as e:
    print(f"\033[31m{e}\033[0m")
    
    
def whoisRemove(result):#Removes data that doesn't give anything usefull

  finds = ("clientTransferProhibited", "Nominet", "domain names", "database contains", "REDACTED", "unsigned", "Domain Name", "URL of the ICANN", "Please query", "Last update", "For more information", "Terms of Use")#Thing to delete
  lines = result.split("\n")#Seperates lines

  while any(find in line for line in lines for find in finds):#Loops through every line
    lines = [line for line in lines if not any (find in line for find in finds)]#Checks for the wanted phrases
  
  filteredLines = []
  skip = 0
  for line in lines:
    if skip > 0:#This will never return true the following arent found
      skip -= 1
    elif "TERMS OF USE" in line:
      skip = 22
    elif "NOTICE" in line:
      skip = 6
    elif "You may not" in line:
      skip = 7
    else:
      filteredLines.append(line)
  lines = filteredLines

  data = "\n".join(lines)#Makes it human readable again
  return (data)
  
def checkSum(data):
  #I still don't fully understand this, but I know it makes the code work so it's here
  sum = 0
  countTo = (len(data) // 2) * 2
  count = 0

  while count < countTo:
    thisVal = data[count + 1] * 256 + data[count]
    sum = sum + thisVal
    sum = sum & 0xffffffff
    count = count + 2

  if countTo < len(data):
    sum = sum + data[-1]
    sum = sum & 0xffffffff

  sum = (sum >> 16) + (sum & 0xffff)
  sum = sum + (sum >> 16)
  answer = ~sum & 0xffff
  return answer >> 8 | (answer << 8 & 0xff00)
  
def osFingerprint(): #This one needs admin to use because of raw sockets
  print ("\nFingerprinting OS With TTL")
  try:
    #Makes a raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(1)
    
    dummy = struct.pack('!BBHHH', 8, 0, 0, 12345, 1) #Makes a dummy header to format the header with the BBHHH
    cheksum = checkSum(dummy+b'HIIII :3') #Uses the dummy to get the correct checksum with a payload to send out
    icmpPacket = struct.pack('!BBHHH', 8, 0, cheksum, 12345, 1)+b'HIIII :3' #The actual packet that will be sent
    
        
    #Sends the packet to the IP and gets the response
    sock.sendto(icmpPacket, (target, 1))
    sock.settimeout(5)
    packet, _ = sock.recvfrom(2000)
    
    ttl = packet[8]
    
    if ttl <= 64:
      print ("\033[32mSuspected OS: Linux/Unix\033[0m")
      if summary.lower() in ["y", "yes"]:
        f.write (f"Suspected OS: Linux/Unix\n\n")
    elif 64 < ttl <= 128:
      print ("\033[32mSuspected OS: Windows\033[0m")
      if summary.lower() in ["y", "yes"]:
        f.write (f"Suspected OS: Windows\n\n")
    elif ttl > 200:
      print ("\033[32mSuspected OS: MacOS\033[0m")
      if summary.lower() in ["y", "yes"]:
        f.write (f"Suspected OS: MacOS\n\n")
    elif 128 < ttl <= 200:
      print ("\033[32mSuspected OS: Custom / Imbeded System\033[0m")
      if summary.lower() in ["y", "yes"]:
        f.write (f"Suspected OS: Custom / Imbeded System\n\n")
    else:
      print ("\033[31mCan't Find OS\033[0m")
  except PermissionError:
    print ("\033[31mNot Running With Admin Privilges\033[0m")
  except socket.timeout:
    print ("\033[31mTimeout\033[0m")
  except Exception as e:
    print(f"\033[31m{e}\033[0m")


#Three way handshake (two way if steath mode is on)
def portScan(port,f,summary):

  global ptotal, btotal, first

  try:
  
    #Sets up connection to the next port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    #Checks if the retrieved port is open
    result = sock.connect_ex((target,port))
    with lock:#Needs to use lock because of multi threading, same thing happens later too
      if first == 1 and local == 0:
        first = 0
        print ("\033[32mConnection Established, Checking Ports\033[0m\n")
    
    #Gets all the info from any open ports that it finds  
    if result == 0: #0 indicates an open port
      with lock:
        ptotal = ptotal + 1
      if stealth.lower() in ["n", "no"]:
        print (f"\033[32m- Port {port} is open -\033[0m")
        print (f"Requesting Port {port} Banner\n")
      else:
        print (f"\033[32m- Port {port} is open -\033[0m\n")
        if summary.lower() in ["y", "yes"]:
          f.write(f"Open Port: {port}\n\n")
        
      if stealth.lower() in ["n", "no"]:
        try:
          sock.settimeout(5)
          bannerRaw = sock.recv(2000) #Requests a banner from the port
          if bannerRaw: #Checks if any data was sent by the port
            try:
              banner = bannerRaw.decode("utf-8").strip() #Converts bytes into readable text
            except UnicodeDecodeError: #This won't flag most of the time, but incase it does it's here
              banner = bannerRaw.decode("latin-1").strip() #These two will catch 99.9% of banners
            print (f"\033[32mPort {port} Banner: \033[35m{banner}\033[32m -\033[0m\n")
            if summary.lower() in ["y", "yes"]:
              f.write (f"Open Port: {port}\n")
              f.write (f"Banner: {banner}\n\n")
            with lock:
              btotal= btotal + 1
          else:
            print(f"Banner For Port {port} Recieved But No Data Avalible")
        except socket.timeout: #The port has no banner, works like an else statement
          print (f"\033[31mPort {port} Banner Timeout\033[0m\n")
          if summary.lower() in ["y", "yes"]:
            f.write (f"Open Port: {port}\n\n")

      sock.close()

  except:
    pass

#Threading to speed up the scan
threads = []

start = (datetime.now().replace(microsecond=0,hour=0)) #Used to give total time at end of scan

infoGrab(target,local,f,summary,ip)

osFingerprint()

print ("\nGetting WHOIS Lookup")

server = (whoisServer(target,ip))

if server is None:
  print ("\033[31mCan't Find Server To Contact\033[0m")
elif server == "NIP":
  print ("\033[31mCannot Get IP To Lookup\033[0m")
elif server != "No Result":
  result = whoisLookup(target,server)
  if result != None:
    whois = (whoisRemove(result))
    print (f"\033[32m{whois}\033[0m")
    print("\033[F\033[F\033[F\033[F")
    if summary.lower() in ["y", "yes"]:
      f.write("WhoIs Lookup:\n")
      f.write(whois)
else:
  print ("\033[31mCan't Contact Server\033[0m")

if local == 0:
  print (f"\nEstablishing Connection To Ports\033[0m")

for port in range(1,65536):
  thread = threading.Thread(target=portScan, args=(port,f,summary))
  thread.start()
  threads.append(thread)

for item in threads:
    item.join()

if summary.lower() in ["y", "yes"]:
  f.close()
  
#Scan statistics
if ptotal == 0:
  print("\033[31mCouldn't find any open ports\033[0m")
elif ptotal == 1:
  print(f"\033[32mFound {ptotal} port\033[0m")
else:
  print(f"\033[32mFound {ptotal} ports\033[0m")
if stealth.lower() in ["n" or "no"]:
  if btotal == 0:
    print("\033[31mCouldn't find any banners\033[0m")
  elif btotal == 1:
    print(f"\033[32mFound {btotal} banner\033[0m")
  else:
    print(f"\033[32mFound {btotal} banners\033[0m")
finish = (datetime.now().replace(microsecond=0,hour=0))
length = finish - start
if length.seconds // 60 >= 1:
    print (f"\nScan took {length.seconds // 60} minutes and {length.seconds % 60} seconds.")
else:
  print (f"\nScan took {length.seconds} seconds.")