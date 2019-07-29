from scapy.all import *
import sys, base64

def raw(p):
    return p[ICMP][Raw].load[16:32]

def isICMP(p):
    return p.haslayer(ICMP) and p[ICMP].type==8

def serverLastBytes(interface):

    try:
        config.conf.iface = interface
    except:
        pass

    for x in range(4):

        s = sniff(lfilter = lambda packet : isICMP(packet),
                  stop_filter = lambda packet : isICMP(packet) and '\n' in raw(packet))

        buf = [raw(i) for i in s]

        # if interface is loopback for testing purposes,
        # each packet is duplicated so we need to remove it

        if interface == "lo":
            buf = [buf[i] for i in range(len(buf)) if i % 2 == 0]

        buf = ''.join(buf)

        print "[*] Buf length   : {}".format(len(buf.encode("hex")))
        print "[*] Received data: \"{}\"".format(base64.b64decode(buf[:buf.find('\n')]))

def serverTimeBased(interface):

    try:
        config.conf.iface = interface
    except:
        pass

    for x in range(4):

        s = sniff(lfilter = lambda packet : isICMP(packet),
                  stop_filter = lambda packet : isICMP(packet) and '\n' in raw(packet))

        # if interface is loopback for testing purposes,
        # each packet is duplicated so we need to remove it

        if interface == "lo":
            s = [s[i] for i in range(len(s)) if i % 2 == 0]

        msg = "1"

        for n in range(1, len(s)):
            diff = int((s[n].time - s[n-1].time) * 10)
            msg += (diff- (1 * (diff % 2 != 0)))/2 * "0" +  ("1" * (diff % 2 != 0))

        data = hex(int(msg, 2))[2:].replace("L", "").decode("hex")
        print "[*] Received data: \"{}\"".format(data)

if __name__ == "__main__":

    interface = "lo"

    serverTimeBased(interface)
