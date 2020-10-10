import socket 
import mmap 
import ctypes
import struct
import select
import dpkt.pcap as dpcap

block_size = 1 << 22 
frame_size = 1 << 11 

block_num = 64 

memory_size = block_num * block_size

frame_num = memory_size // frame_size
print(block_size,block_num,frame_size,frame_num)

ETH_P_ALL = 0x0003


sock = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(ETH_P_ALL))

print(sock.fileno())

SOL_PACKET = 263
PACKET_VERSION = 10
v = 2

sock.setsockopt(SOL_PACKET,PACKET_VERSION,v)

class tpacket_req3():
    _struct_pattern = 'IIIIIII'
    def __init__(self,block_size:int, block_num:int, frame_size:int,frame_num:int):
        self.tp_block_size = block_size
        self.tp_block_num = block_num 
        self.tp_frame_size = frame_size 
        self.tp_frame_nr = frame_num 
        self.tp_retire_blk_tov = 60 
        self.tp_sizeof_priv = 0
        self.tp_feature_req_word = 1
    def toConvert(self):
        return struct.pack(self._struct_pattern,self.tp_block_size,self.tp_block_num,
        self.tp_frame_size,self.tp_frame_nr,self.tp_retire_blk_tov,self.tp_sizeof_priv,self.tp_feature_req_word)

req3 = tpacket_req3(block_size,block_num,frame_size,frame_num)

PACKET_RX_RING = 5 

ret = sock.setsockopt(SOL_PACKET,PACKET_RX_RING,req3.toConvert())

MAP_LOCKED	= 0x02000

mm = mmap.mmap(sock.fileno(),memory_size,mmap.MAP_SHARED|MAP_LOCKED,
    mmap.PROT_READ|mmap.PROT_WRITE)
# unpack_format     
# struct.unpack_from()
print(socket.PACKET_HOST)
sock.bind(('vboxnet0',0,0,0))

class block_desc(ctypes.Structure):
    _fields_ = [('version',ctypes.c_uint),
                ('offset_to_priv',ctypes.c_uint),
                ('block_status',ctypes.c_uint),
                ('num_pkts',ctypes.c_uint),
                ('offset_to_first_pkt',ctypes.c_uint)]
class tpacket3_hdr(ctypes.Structure):
    _fields_ = [('tp_next_offset',ctypes.c_uint32),
    ('tp_sec',ctypes.c_uint32),
    ('tp_nsec',ctypes.c_uint32),
    ('tp_snaplen',ctypes.c_uint32),
    ('tp_len',ctypes.c_uint32),
    ('tp_status',ctypes.c_uint32),
    ('tp_mac',ctypes.c_uint16),
    ('tp_net',ctypes.c_uint16),
    ]

class ether_hdr(ctypes.Structure):
    _fields_ = [('h_dest',ctypes.c_ubyte*6),
    ('h_source',ctypes.c_ubyte*6),
    ('h_proto',ctypes.c_ushort)]

pfd = select.poll()
READ_ONLY = select.POLLIN | select.POLLERR
pfd.register(sock,READ_ONLY)
i = 0

# bdesc = block_desc.from_buffer_copy(mm)
TP_STATUS_USER = 1 << 0 
TP_STATUS_KERNEL = 0
fpcap = open("./tmp.pcap",'wb')
fwrite = dpcap.Writer(fpcap)

def display(bdesc:object,length:int):
    pkt_nums = bdesc.num_pkts
    tmp = bdesc.offset_to_first_pkt + length
    th3 = tpacket3_hdr.from_buffer(mm,tmp)
    for i in range(pkt_nums):
        eth = ether_hdr.from_buffer(mm,tmp+th3.tp_mac)
        one = socket.ntohs(eth.h_proto)
        print(eth.h_dest[0],eth.h_dest[1],eth.h_dest[2],eth.h_dest[3],eth.h_dest[4],eth.h_dest[5])
        print(eth.h_source[0],eth.h_source[1],eth.h_source[2],eth.h_source[3],eth.h_source[4],eth.h_source[5])
        pkt_tmp = mm[tmp+th3.tp_mac:tmp+th3.tp_mac+th3.tp_snaplen]
        fwrite.writepkt(pkt_tmp)
        print(one,0x0800)
        tmp = tmp + th3.tp_next_offset
        th3 = tpacket3_hdr.from_buffer(mm,tmp)


while True:
    bdesc = block_desc.from_buffer(mm,i*block_size)
    if (bdesc.block_status & TP_STATUS_USER) == 0:
        pfd.poll(-1)
        continue
    print("block {} pkt num {}, offset_to_first_pkt {}".format(i,bdesc.num_pkts,bdesc.offset_to_first_pkt))
    display(bdesc,i*block_size)
    bdesc.block_status = TP_STATUS_KERNEL
    del bdesc
    i = i + 1
    i = i % block_num
fwrite.close()
mm.close()
sock.close()