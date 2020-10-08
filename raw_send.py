import socket 
import mmap 
import struct 
import ctypes 
import select 
import fcntl 

sock = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,0)

SOL_PACKET = 263
PACKET_LOSS = 14
v = 1 
sock.setsockopt(SOL_PACKET,PACKET_LOSS,v)

block_size = 4096 
block_nr = 5 
frame_size = 2048 
frame_nr = 10

PACKET_VERSION = 10
v=1 

sock.setsockopt(SOL_PACKET,PACKET_VERSION,v)

PACKET_QDISC_BYPASS = 20 

v = 1 

sock.setsockopt(SOL_PACKET,PACKET_QDISC_BYPASS,v)

class tpacket_req():
    _struct_pattern = '4I'
    def __init__(self,block_size:int,block_nr:int,frame_size:int,frame_nr:int):
        self.block_size = block_size
        self.block_nr = block_nr 
        self.frame_size = frame_size 
        self.frame_nr = frame_nr
    def toConvert(self):
        return struct.pack(self._struct_pattern,self.block_size,self.block_nr,self.frame_size,self.frame_nr)
PACKET_TX_RING = 13 

req = tpacket_req(block_size,block_nr,frame_size,frame_nr)

sock.setsockopt(SOL_PACKET,PACKET_TX_RING,req.toConvert())

MAP_LOCKED	= 0x02000
MAP_POPULATE = 0x08000

memory_size = block_nr * block_size

mm = mmap.mmap(sock.fileno(),memory_size,mmap.MAP_SHARED|MAP_LOCKED|MAP_POPULATE,
    mmap.PROT_READ|mmap.PROT_WRITE)

ifreq = '16sH14s'
iodata = struct.pack(ifreq,b"vboxnet0",0,b'')
SIOCGIFHWADDR = 0x8927

res = fcntl.ioctl(sock,SIOCGIFHWADDR,iodata,1)

sock.bind(('vboxnet0',0,0,0))

frame_map_format = 'IIIHHIIHH4xHHiHBB8B'
frame_header = struct.calcsize(frame_map_format)
i = 0
TP_STATUS_SEND_REQUEST = 1
TP_STATUS_SENDING = 1 << 1
MSG_DONTWAIT = 0x40
tmp_packet =b'\x00\x12\xc0\x02\xac\x56\x00\x12\xc0\x00\x00\x00\x08\x00\x45\x00\x00\x2e\x00\x00\x40\x00\x40\x06\x00\x00\x0a\x0a\x58\x00\x0a\x0a\x58\xac\x00\x00\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x50\x10\x00\x10\x00\x00\x00\x00\x41\x43\x4b\x73\x77\x66'
packet_len = len(tmp_packet)
while True:
    tp_status,tp_len,tp_snaplen,*l_all = struct.unpack_from(frame_map_format,mm,frame_size*i)
    if tp_status & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING):
        sock.sendto(b'',MSG_DONTWAIT,('vboxnet0',0,0,0))
        continue

    tp_status = TP_STATUS_SEND_REQUEST 
    tp_len = packet_len
    tp_snaplen = packet_len
    struct.pack_into('III',mm,i*frame_size,tp_status,tp_len,tp_snaplen)
    struct.pack_into('60s',mm,i*frame_size+32,tmp_packet)
    i = (i + 1) % frame_nr
mm.close()
sock.close()


