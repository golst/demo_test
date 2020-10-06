#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<assert.h>
#include<stdbool.h>
#include<ifaddrs.h>
#include<errno.h>
#include<unistd.h>
#include<string.h>
#include<stddef.h>
#include<arpa/inet.h>
#include<net/if_arp.h>
#include<sys/types.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<sys/mman.h>
#include<linux/if_ether.h>
#include<linux/if_packet.h>
#include<linux/sockios.h>
#include<linux/if.h>
#include<linux/ethtool.h>
#include<linux/wireless.h>
// static __inline__ __u32 ethtool_cmd_speed(const struct ethtool_cmd *ep)
// {
// 	return (ep->speed_hi << 16) | ep->speed;
// }
#define panic printf
#define unlikely(func) (func)
#define __aligned_tpacket	__attribute__((aligned(TPACKET_ALIGNMENT)))
#define __align_tpacket(x)	__attribute__((aligned(TPACKET_ALIGN(x))))

struct ring {
	struct iovec *frames;
	uint8_t *mm_space;
	size_t mm_len;
	struct sockaddr_ll s_ll;
	union {
		struct tpacket_req layout;
#ifdef HAVE_TPACKET3
		struct tpacket_req3 layout3;
#endif
		uint8_t raw;
	};
};
size_t strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;

		memcpy(dest, src, len);
		dest[len] = '\0';
	}

	return ret;
}
uint32_t ethtool_bitrate(const char *ifname)
{
	int ret, sock;
	uint32_t bitrate;
	struct ifreq ifr;
	struct ethtool_cmd ecmd;

	sock = af_socket(AF_INET);

	memset(&ecmd, 0, sizeof(ecmd));

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ecmd.cmd = ETHTOOL_GSET;
	ifr.ifr_data = (char *) &ecmd;

	ret = ioctl(sock, SIOCETHTOOL, &ifr);
	if (ret) {
		bitrate = 0;
		goto out;
	}

	bitrate = ethtool_cmd_speed(&ecmd);
	if (bitrate == SPEED_UNKNOWN)
		bitrate = 0;
out:
	close(sock);

	return bitrate;
}
uint32_t device_bitrate(const char *ifname)
{
	uint32_t scopper = 0;

	scopper = ethtool_bitrate(ifname);
    return scopper;
	// return scopper ? : wireless_bitrate(ifname);
}
#define CO_IN_CACHE_SHIFT		7
#define CO_CACHE_LINE_SIZE	(1 << CO_IN_CACHE_SHIFT)
#define round_up(x, alignment)	(((x) + (alignment) - 1) & ~((alignment) - 1))
#define round_up_cacheline(x)	round_up((x), CO_CACHE_LINE_SIZE)
static inline size_t ring_size(const char *ifname, size_t size)
{
	if (size > 0)
		return size;

	/*
	 * Device bitrate in bytes times two as ring size.
	 *    Fallback => ~    64,00 MB
	 *     10 MBit => ~     2,38 MB
	 *     54 MBit => ~    12,88 MB
	 *    100 MBit => ~    23,84 MB
	 *    300 MBit => ~    71,52 MB
	 *  1.000 MBit => ~   238,42 MB
	 * 10.000 MBit => ~ 2.384.18 MB
	 */
	size = device_bitrate(ifname);
	size = (size * 1000000) / 8;
	size = size * 2;
	if (size == 0)
		size = 1 << 26;

	return round_up_cacheline(size);
}
int af_socket(int af)
{
	int sock;

	if (unlikely(af != AF_INET && af != AF_INET6))
		panic("Wrong AF socket type!\n");

	sock = socket(af, SOCK_DGRAM, 0);
	if (unlikely(sock < 0))
		panic("Creation AF socket failed: %s\n", strerror(errno));

	return sock;
}
int pf_socket(void)
{
	int sock = socket(PF_PACKET, SOCK_RAW, 0);
	if (unlikely(sock < 0))
		panic("Creation of PF socket failed: %s\n", strerror(errno));

	return sock;
}
int __device_ifindex(const char *ifname)
{
	int ret, sock, index;
	struct ifreq ifr;

	if (!strncmp("any", ifname, strlen("any")))
		return 0;

	sock = af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFINDEX, &ifr);
	if (ret)
		index = -1;
	else
		index = ifr.ifr_ifindex;

	close(sock);

	return index;
}

int device_ifindex(const char *ifname)
{
	int index = __device_ifindex(ifname);

	if (unlikely(index < 0))
		panic("Cannot get ifindex from device!\n");

	return index;
}
int device_type(const char *ifname)
{
	int ret, sock, type;
	struct ifreq ifr;

	if (!strncmp("any", ifname, strlen("any")))
		return ARPHRD_ETHER;

	sock = af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFHWADDR, &ifr);
	if (unlikely(ret))
		panic("Cannot get iftype from device!\n");

	/* dev->type */
	type = ifr.ifr_hwaddr.sa_family;
	close(sock);

	return type;
}
struct frame_map {
	struct tpacket2_hdr tp_h __aligned_tpacket;
	struct sockaddr_ll s_ll __align_tpacket(sizeof(struct tpacket2_hdr));
};
static void set_packet_loss_discard(int sock)
{
	int ret, discard = 1;
	ret = setsockopt(sock, SOL_PACKET, PACKET_LOSS, (void *) &discard,
			 sizeof(discard));
	if (ret < 0)
		panic("setsockopt: cannot set packet loss");
}
#define RUNTIME_PAGE_SIZE	(sysconf(_SC_PAGE_SIZE))
static inline void shrink_ring_layout_generic(struct ring *ring)
{
	ring->layout.tp_block_nr >>= 1;
	ring->layout.tp_frame_nr = ring->layout.tp_block_size /
				   ring->layout.tp_frame_size *
				   ring->layout.tp_block_nr;
}
static void create_tx_ring(int sock, struct ring *ring, bool verbose)
{
	int ret;
retry:
	ret = setsockopt(sock, SOL_PACKET, PACKET_TX_RING, &ring->layout,
			 sizeof(ring->layout));
    panic("22222222222222Cannot allocate TX_RING!%d , %s\n",errno,strerror(errno));

	if ((errno == EINVAL || errno == ENOMEM) && ring->layout.tp_block_nr > 1) {
		shrink_ring_layout_generic(ring);
		panic("111111111111111111Cannot allocate TX_RING!\n");
		goto retry;
	}

	if (ret < 0)
		panic("Cannot allocate TX_RING!\n");

	ring->mm_len = (size_t) ring->layout.tp_block_size * ring->layout.tp_block_nr;

	if (verbose) {
		printf("TX,V2: %.2Lf MiB, %u Frames, each %u Byte allocated\n",
		       (long double) ring->mm_len / (1 << 20),
		       ring->layout.tp_frame_nr, ring->layout.tp_frame_size);
	}
}
void mmap_ring_generic(int sock, struct ring *ring)
{
	ring->mm_space = mmap(NULL, ring->mm_len, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_LOCKED | MAP_POPULATE, sock, 0);
	if (ring->mm_space == MAP_FAILED)
		panic("Cannot mmap {TX,RX}_RING!\n");
}
static inline void xlockme(void)
{
	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
		panic("Cannot lock pages!\n");
}
#define bug_on(cond)		assert(!(cond))

static inline void ring_verify_layout(struct ring *ring)
{
	bug_on(ring->layout.tp_block_size  < ring->layout.tp_frame_size);
	bug_on((ring->layout.tp_block_size % ring->layout.tp_frame_size) != 0);
	bug_on((ring->layout.tp_block_size % RUNTIME_PAGE_SIZE) != 0);
}
void *xmalloc_aligned(size_t size, size_t alignment)
{
	int ret;
	void *ptr;

	if (unlikely(size == 0))
		panic("xmalloc_aligned: zero size\n");

	ret = posix_memalign(&ptr, alignment, size);
	if (unlikely(ret != 0))
		panic("xmalloc_aligned: out of memory (allocating %zu "
		      "bytes)\n", size);

	return ptr;
}
void *xzmalloc_aligned(size_t size, size_t alignment)
{
	void *ptr = xmalloc_aligned(size, alignment);
	memset(ptr, 0, size);
	return ptr;
}
void alloc_ring_frames_generic(struct ring *ring, size_t num, size_t size)
{
	size_t i, len = num * sizeof(*ring->frames);

	ring->frames = xzmalloc_aligned(len, CO_CACHE_LINE_SIZE);

	for (i = 0; i < num; ++i) {
		ring->frames[i].iov_len = size;
		ring->frames[i].iov_base = ring->mm_space + (i * size);
	}
}
void bind_ring_generic(int sock, struct ring *ring, int ifindex, bool tx_only)
{
	int ret;

	/* The {TX,RX}_RING registers itself to the networking stack with
	 * dev_add_pack(), so we have one single RX_RING for all devs
	 * otherwise you'll get the packet twice.
	 */
	memset(&ring->s_ll, 0, sizeof(ring->s_ll));

	ring->s_ll.sll_family = AF_PACKET;
	ring->s_ll.sll_ifindex = ifindex;
	ring->s_ll.sll_protocol = tx_only ? 0 : htons(ETH_P_ALL);

	ret = bind(sock, (struct sockaddr *) &ring->s_ll, sizeof(ring->s_ll));
	if (ret < 0)
		panic("Cannot bind {TX,RX}_RING!\n");
}
static inline int user_may_pull_from_tx(struct tpacket2_hdr *hdr)
{
	return !(hdr->tp_status & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING));
}

static inline void kernel_may_pull_from_tx(struct tpacket2_hdr *hdr)
{
	hdr->tp_status = TP_STATUS_SEND_REQUEST;
}
static inline int pull_and_flush_tx_ring_wait(int sock)
{
	return sendto(sock, NULL, 0, 0, NULL, 0);
}
int main(int argc, char* argv[])
{
    int ifindex = device_ifindex(argv[1]);
    int type =device_type(argv[1]);
    int size = ring_size(argv[1],0);
    struct ring ring;
    int sock = pf_socket();
	struct frame_map *hdr;
	uint8_t *out = NULL;
    bool jumbo_support = false;
	int retry = 100;
    xlockme();
	memset(&ring, 0, sizeof(ring));
    set_packet_loss_discard(sock);
	memset(&ring.layout, 0, sizeof(ring.layout));
	ring.layout.tp_block_size = (jumbo_support ?
				      RUNTIME_PAGE_SIZE << 4 :
				      RUNTIME_PAGE_SIZE << 2);

	ring.layout.tp_frame_size = (jumbo_support ?
				      TPACKET_ALIGNMENT << 12 :
				      TPACKET_ALIGNMENT << 7);

	ring.layout.tp_block_nr = size / ring.layout.tp_block_size;
	ring.layout.tp_frame_nr = size / ring.layout.tp_frame_size;
	ring.layout.tp_block_size = 4096;
	ring.layout.tp_frame_size = 2048;
	ring.layout.tp_block_nr = 5;
	ring.layout.tp_frame_nr = 10;
    printf("ifindex %d;type %d;rate %d\n",ifindex,type,ring_size);
    printf("ring block_size %d; block_num %d; frame_size %d; frame_num %d;\n",
        ring.layout.tp_block_size,ring.layout.tp_block_nr,ring.layout.tp_frame_size,ring.layout.tp_frame_nr);
    int val = TPACKET_V2;
    int ret = setsockopt(sock, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));
	if (ret)
		panic("Cannot set tpacketv2!\n");
	val = 1;
	ret = setsockopt(sock, SOL_PACKET, PACKET_QDISC_BYPASS, &val, sizeof(val));
	if(ret < 0)
		panic("Cannot set PACKET_QDISC_BYPASS!\n");
    ring_verify_layout(&ring);
    create_tx_ring(sock,&ring,true);
    mmap_ring_generic(sock,&ring);
	alloc_ring_frames_generic(&ring,ring.layout.tp_frame_nr,ring.layout.tp_frame_size);
	bind_ring_generic(sock,&ring,ifindex,true);
	int num = 10;
	int it = 0;
	uint8_t packet[] = {0x00,0x12, 0xc0,0x02, 0xac, 0x56, 0x00, 0x12, 0xc0, 0x00,0x00,0x00,0x08,0x00,0x45,0x00,0x00,0x2e,
	 0x00,0x00,0x40,0x00,0x40,0x06,0x00,0x00,0x0a,0x0a,0x58,0x00,0x0a,0x0a, 0x58, 0xac,
	  0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x50,0x10,0x00 ,0x10, 0x00, 0x00, 0x00, 0x00, 0x41 ,0x43, 0x4b, 0x73, 0x77, 0x66};
	int leng = sizeof(packet);
	while(num>0)
	{
		if(!user_may_pull_from_tx(ring.frames[it].iov_base))
		{
			panic("-------------it %d---------22\n",it);

			int ret = sendto(sock, NULL, 0, MSG_DONTWAIT, NULL, 0);
			if(ret < 0)
			{
				if(errno != EBADF && errno != ENOBUFS)
				{
					panic("Flushing TX_RING failed: %s!\n", strerror(errno));
				}
			}
			continue;
		}
		hdr = ring.frames[it].iov_base;
		out = ((uint8_t *) hdr) + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);

		hdr->tp_h.tp_snaplen = leng;
		hdr->tp_h.tp_len = leng;

		memcpy(out,packet,leng);

		panic("-----------i %d-----------11\n",num);

		kernel_may_pull_from_tx(&hdr->tp_h);

		it++;
		num--;
		if(num == 0)
		{
			num = 10;
			it = 0;
		}
	}
	while (pull_and_flush_tx_ring_wait(sock) < 0 && errno == ENOBUFS && retry-- > 0)
		usleep(10000);
    close(sock);
}