import optparse
import socket
from socket import *
import threading
import nmap

screenLock = threading.Semaphore(value=1)


def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('ViolentPython\r\n')
        results = connSkt.recv(100)
        screenLock.acquire()
        print("[+] %d/tcp open" % tgtPort)
        print("[+] " + str(results))

    except:
        screenLock.acquire()
        print("[-] %d/tcp closed" % tgtPort)

    finally:
        screenLock.release()
        connSkt.close()

def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print("[-] Cannot resolve '%s': Unknown host\n" % tgtHost)
        return
    try:
        tgtName = gethostbyaddr(tgtIP)
        print("[+] Scan Results for: \n" + tgtName[0])
    except:
        print("[+] Scan Results for \n" + tgtIP)

    setdefaulttimeout(1)

    for tgtPort in tgtPorts:
        t = threading.Thread(target=connScan, args=(tgtHost, int(tgtPort)))
        t.start()

def nmapScan(tgtHost, tgtPort):
    tgtIP = gethostbyname(tgtHost)
    nmScan = nmap.PortScanner()
    nmScan.scan(tgtIP, tgtPort)
    state = nmScan[tgtIP]['tcp'][int(tgtPort)]['state']
    print(" [*] "+tgtHost+"/"+tgtIP+" tcp/"+tgtPort+" "+state )


def main():
    parser = optparse.OptionParser('usage %prog -H <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    #option is given by ' ' or ',' can be splited
    tgtPorts = str(options.tgtPort).split(', ')
    #if no option given, return usage and exit
    if (tgtHost == None) | (tgtPorts == None):
        print("[-] You must specify a target host and port[s]")
        exit(0)

    for tgtPort in tgtPorts:
        t = threading.Thread(target=nmapScan, args=(tgtHost, tgtPort))
        t.start()

if __name__ == '__main__':
    main()
