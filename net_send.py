from netsuit.sockets.pfsocket import txRawSocket
from random import randint
import array
import sys

from dpkt import ethernet
from dpkt import ip
from dpkt import tcp 

sock = txRawSocket('vboxnet0')
# sock = txRawSocket('eth2')

def checksum(pkt):
    if len(pkt) % 2 == 1:
        pkt += b"\0"
    s = sum(array.array('H',pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    if sys.byteorder == 'little':
        s = (s >> 8 & 0xff) | s << 8
    return s & 0xffff

tmp_packet =b'\x00\x12\xc0\x02\xac\x56\x00\x12\xc0\x00\x00\x00\x08\x00\x45\x00\x00\x2e\x00\x00\x40\x00\x40\x06\x00\x00\x0a\x0a\x58\x00\x0a\x0a\x58\xac\x00\x00\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x50\x10\x00\x10\x00\x00\x00\x00\x41\x43\x4b\x73\x77\x66'

def getOnebyte():
    tmp = randint(0,255)
    return tmp.to_bytes(1,byteorder='big',signed=False)


eth = ethernet.Ethernet()

eth.src = b'\x00\x12\xc0\x02\xac' + getOnebyte()
eth.dst = b'x00\x12\xc0\x00\x00\x00'

eth_ip = ip.IP()

ip_tcp = tcp.TCP()

ip_tcp.sport = 8080
ip_tcp.dport = 80

ip_tcp.seq = 0x01
ip_tcp.ack =0x88

ip_tcp.flags = tcp.TH_SYN

ip_tcp.data = b'asasdadadadasdasdasdas'

eth_ip.len = len(ip_tcp) + 20

eth_ip.id =0x1234

eth_ip.df=1

eth_ip.p = ip.IP_PROTO_TCP

eth_ip.src = b'\xac\xa8\x01' + getOnebyte()
eth_ip.dst = b'\xac\xa8\x01\x01'

tmp = eth_ip.src + eth_ip.dst + eth_ip.p.to_bytes(2,'big',signed=False) + eth_ip.len.to_bytes(2,'big',signed=False)

tmp += ip_tcp.pack()

#print(type(tmp))

ip_tcp.sum = checksum(tmp)


eth_ip.sum = checksum(eth_ip.pack_hdr())

eth_ip.data = ip_tcp.pack()

eth.data = eth_ip.pack()

tmp_packet = eth.pack()

sock.send_packets(tmp_packet)
