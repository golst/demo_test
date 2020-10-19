from netsuit.sockets.pfsocket import rxRawSocket
from netsuit.pcap.pcap import Writer
from dpkt.ethernet import Ethernet
from multiprocessing import Process,Pipe
import time
fpcap = open("./tmp.pcap",'wb')
fwrite = Writer(fpcap)
sock =rxRawSocket("vboxnet0")
i = 0
for packet in sock.rx_fast_packets():
    fwrite.writepkt(packet)
    i += 1
    print("num:  %d" % i)
    
parent_conn, child_conn = Pipe()
fpcap = open("./tmp.pcap",'wb')
fwrite = Writer(fpcap)
def multi_process(conn):
    print("start")
    sock = rxRawSocket("vboxnet0")
    tmp = sock.rx_packets(conn)
    next(tmp)

p = Process(target=multi_process,args=(child_conn,))
p.start()
num = 0
while True:
    one = parent_conn.recv_bytes()
    fwrite.writepkt(one)
    num += 1
    print("num: ",num)

sock = rxRawSocket("vboxnet0")

i = 0
# getPack = sock.rx_packets()
for packet in sock.rx_packets(None):
    fwrite.writepkt(packet)
    i += 1
    print("num:  %d" % i)


