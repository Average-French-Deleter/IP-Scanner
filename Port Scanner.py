import sys
import socket
from datetime import datetime
import errno
import os
import time
import threading
import requests
import subprocess
import uuid
import struct

first = 1
ptotal = 0
btotal = 0
local = 0
noGeo = 0
f = 0
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

print ("Do you want to fingerprint the OS of the selected IP?")
print ("This will require administrator/root as it creates raw ports.")
fingerprint = input("\nFingerprint OS? (Y/N)")
while fingerprint.lower() not in ["y", "yes", "n", "no"]:
  print("\nCan't recognise an answer, please input correctly.")
  fingerprint = input("Fingerprint OS? (Y/N)")

title()

print("Info:\nThis scanner uses IPv4, if you're not sure if you have a v4 or v6 IP, then it's probably a v4.")
print("The intended purpose is for education and to be used with personally owned IPs.")
print("Unauthorised use of this tool on someone elses IP is not condoned and is your responsibility.")
print ("Domain names will also work and will give you its IP if you do enter one.")
if stealth.lower() in ["n" or "no"]:
  print("Some IPs may block this tool with stealth scan off, if you're not getting many ports with it off, try one with it on.")
print ("(ctrl+c won't work because of multi threading, just wait for it to finish)")

target = input(str("\n\n\033[32mIP/Domain To Scan:\033[0m"))

if target == "" or target == "127.0.0.1" or target == "localhost":
  local = 1

if summary.lower() in ["y", "yes"]:
  if f"{target} Scan Results.txt" in os.listdir():
    print (f"\nThere is already a file made for {target}, would you like to overwrite it?")
    overwrite = input("Overwrite File? (Y/N)")
    if overwrite.lower() in ["y", "yes"]:
      with open (f"{target} Scan Results.txt", "w"):
        pass

title()

if summary.lower() in ["y", "yes"]:
  f = open(f"{target} Scan Results.txt", "a")
  if overwrite.lower() in ["n", "no"]:
    f.write ("\nDuplicate Scan:\n\n")

#Signiling start of scan to user and some statistics

def infoGrab(target,local,f,summary):
  
  #This still doesn't write to the text file properly when it's suppsoed to
  
  if local == 1:
    print ("\n\033[35m- Scan Start -\033[0m")
    print (f"Time Of Scan: {str(datetime.now().replace(microsecond=0))}")
    print ("\nScanning Local Host Ports\n")
  
  else:
    print ("\n\033[35m- Scan Start -\033[0m")
    print (f"Time Of Scan: {str(datetime.now().replace(microsecond=0))}")
  
    print (f"Scanning \033[34m{target}\033[0m")
    if target.count(".") != 3: #Checks if it's not an ip
      ip = socket.gethostbyname(target)
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
      url = (f"https://ipinfo.io/{target}/json") #Site for info on IPs
    else:
      url = (f"https://ipinfo.io/{ip}/json") #The site won't work with domains so if a domain is entered it uses the IP gotten earlier
    try:
      respond = requests.get(url)
      isp = respond.json() #Converts json into something readable by python
      if "org" in isp:
        print (f"\033[32mISP Found: {isp['org']}\033[0m")
        if summary.lower() in ["y", "yes"]:
          f.write (f"ISP: {isp['org']}\n\n")
      else:
        print ("\033[31mNo ISP Found\033[0m")
    except:
      print ("\033[31mCouldn't Check For ISP\033[0m") 
      
    print ("\nSearching For Server Geolocation")
    try:
      respond = requests.get(url) #Uses the same site as for ISP
      geolocation = respond.json()  # Converts JSON into something readable by Python
      if "country" in geolocation:
        print(f"\033[32mCountry: {geolocation['country']}\033[0m")
        if summary.lower() in ["y", "yes"]:
          f.write (f"Country Of Server: {geolocation['country']}\n")
      else:
        noGeo = 1
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
  
  
def osFingerprint(): #This one needs admin to use because of raw sockets
  print ("\nFingerprinting OS With TTL")
  try:
    #Makes a raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(1)
    
    #Sends an emptry packet to the IP and gets the 
    sock.sendto(b'', (target_ip, 1))
    packet, _ = sock.recvfrom(2000)
    ttl = packet[8]
    if ttl is None:
        print ("\033[31mCan't Find OS\033[0m")
    elif ttl <= 64:
        print ("\033[32mSuspected OS: Linux/Unix\033[0m")
    elif ttl == 128:
        print ("\033[32mSuspected OS: Windows\033[0m")
    elif ttl == 255:
        print ("\033[32mSuspected OS: MacOS\033[0m")
    else:
      print ("\033[31mCan't Find OS\033[0m")
  except Exception as e:
    print(f"\033[31m\n{e}\033[0m")
    pass


#Three way handshake (two way if steath mode is on)
def portScan(port,f,summary):

  global ptotal, btotal, first

  try:
  
    #Sets up connection to the next port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    #Checks if the retrieved port is open
    result = sock.connect_ex((target,port))
    if first == 1 and local == 0:
      with lock: #Needs to use lock because of multi threading, same thing happens later too
        print ("\033[32mConnection Established, Checking Ports\033[0m\n")
        first = 0
    
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

infoGrab(target,local,f,summary)

if fingerprint in ["y", "yes"]:
  osFingerprint()

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
  