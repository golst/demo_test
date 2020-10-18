from netsuit.sockets.pfsocket import rxRawSocket
from netsuit.pcap.pcap import Writer
from dpkt.ethernet import Ethernet

sock = rxRawSocket("vboxnet0")

i = 0
for packet in sock.rx_packets():
    eth = Ethernet(packet)
    print(eth.src,"--------->",eth.dst,"---proto:",eth.type)

    i +=1
    print("num %d" % i)


