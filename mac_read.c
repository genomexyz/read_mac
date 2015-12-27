#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define MAC_LEN 6
#define IP_LEN 4
#define ETHER_FRAME_LEN 14
#define ARP_TOTAL_LEN 44
#define ARP_PROTO 0x0806
#define BRODCAST_PKT "\xff\xff\xff\xff\xff\xff"
#define ARP_PACKET "\x08\x06"
#define ARP_REPLY "\x00\x02"
#define HARDWARE_TYPE 0x0001
#define PROTOCOL_TYPE 0x0800
#define HARDWARE_SIZE 6
#define PROTOCOL_SIZE 4
#define OPCODE 0x0001

char* create_pkt (char *ip)
{
	char *ptr;
	char *adr;
	char *token;
	int fd;
	int arp_proto = htons(ARP_PROTO);
	int hw_tp = htons(HARDWARE_TYPE);
	int pro_type = htons(PROTOCOL_TYPE);
	int hw_size = HARDWARE_SIZE;
	int pr_size = PROTOCOL_SIZE;
	int opcode = htons(OPCODE);
	int i;
	unsigned char seq;
	struct ifreq buffer;
	struct sockaddr_in *ipadd;

	ptr = malloc(sizeof(char [ARP_TOTAL_LEN]));
	memset(ptr, 0x00, sizeof (char [ARP_TOTAL_LEN]));
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	memset(&buffer, 0, sizeof(buffer));
	strcpy(buffer.ifr_name, "wlan0");
	ioctl(fd, SIOCGIFHWADDR, &buffer);
	close(fd);
	memcpy(ptr, BRODCAST_PKT, MAC_LEN);
	memcpy(ptr + MAC_LEN, buffer.ifr_addr.sa_data, MAC_LEN);
	memcpy(ptr + (2 * MAC_LEN), &arp_proto, 2);
	memcpy(ptr + ETHER_FRAME_LEN, &hw_tp, 2);
	memcpy(ptr + ETHER_FRAME_LEN + 2, &pro_type, 2);
	memcpy(ptr + ETHER_FRAME_LEN + 4, &hw_size, 1);
	memcpy(ptr + ETHER_FRAME_LEN + 5, &pr_size, 1);
	memcpy(ptr + ETHER_FRAME_LEN + 6, &opcode, 2);
	memcpy(ptr + ETHER_FRAME_LEN + 8, buffer.ifr_addr.sa_data, MAC_LEN);
	memset(&buffer, 0, sizeof buffer);
	strcpy(buffer.ifr_name, "wlan0");
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ioctl(fd, SIOCGIFADDR, &buffer) == -1)
		printf("ioctl ip checking error\n");
	close(fd);
	ipadd = (struct sockaddr_in *) &(buffer.ifr_addr);
	adr = inet_ntoa(ipadd->sin_addr);
	printf("alamat ipmu adalah : %s\n", adr);
	token = strtok(adr, ".");
	while (token != NULL) {
		seq = atoi(token);
		memcpy(ptr + ETHER_FRAME_LEN + 8 + MAC_LEN + i, &seq, 1);
		token = strtok(NULL, ".");
		i++;
	}
	i = 0;
	token = strtok(ip, ".");
	while (token != NULL) {
		seq = atoi(token);
		memcpy(ptr + ETHER_FRAME_LEN + 8 + (2 * MAC_LEN) + IP_LEN + i, &seq, 1);
		token = strtok(NULL, ".");
		i++;
	}

	return ptr;
}

int are_equal (const unsigned char *str1, const unsigned char *str2, int len)
{
	int i;
	
	for (i = 0; i < len; i++) {
		if (!(*(str1 + i) & *(str2 + i)))
			return 0;
	}

	return 1;
}

int create_socket ()
{
	int fd;

	fd = socket(AF_PACKET, SOCK_RAW, htons(0x0806));
	if (fd == -1)
		printf("socket error\n");

	return fd;
}

int examine_addr (char *addr)
{
	char *ex;
	char sec_addr [3];
	char *token;
	unsigned int tes;
	int chk_ip = 0;
	
	ex = strchr(addr, ' ');
	if (ex != NULL) {
		printf("alamat yang di masukkan salah, mohon jangan ada spasi\n");
		return 0;
	}
	token = strtok(addr, ".");
	while (token != NULL) {
		chk_ip++;
		tes = atoi(token);
		if (tes > 255) {
			printf("alamat ip tidak ada yang lebih dari 255\n");
			return 0;
		}
		token = strtok(NULL, ".");
	}
	if (chk_ip != 4) {
		printf("alamat tidak valid\n");
		return 0;
	}

	return 1;
}

int main ()
{
	unsigned char ip_target [4];
	unsigned char arp [2];
	unsigned char seq;
	char ip [15];
	char fill [15];
	unsigned char second_fill [15];
	unsigned char fountain_fill [15];
	unsigned char mac_target [6];
	char *pkt;
	char *token;

	int sock;
	int size;
	int i;
	struct sockaddr_ll ll = {0}; //very important
	
	printf("masukkan alamat yang ingin dicari mac addressnya\n");
	scanf("%15s", ip);
	memcpy(fill, ip, sizeof (char [15]));
	memcpy(second_fill, ip, sizeof (char [15]));
	memcpy(fountain_fill, ip, sizeof (char [15]));
	if (examine_addr(ip)) {
		sock = create_socket();
		pkt = create_pkt(fill);
		
		//filling sockaddr_ll
		ll.sll_family = AF_PACKET;
		ll.sll_ifindex = if_nametoindex("wlan0");
		ll.sll_halen = 6;
		memcpy(ll.sll_addr, "\xff\xff\xff\xff\xff\xff", 6);

		//send arp request
		sendto(sock, pkt, sizeof (char [ARP_TOTAL_LEN]), 0, (struct sockaddr *) &ll, sizeof (ll));

		//detect mac
		free(pkt);
		pkt = malloc(sizeof (char [1024]));
		size = sizeof (ll);
		while (1) {
			if (recvfrom(sock, pkt, 1024, 0, (struct sockaddr *) &ll, (socklen_t *) &size) == -1)
				printf("error at receiving packet\n");
			memcpy(&arp, pkt + ETHER_FRAME_LEN - 2, 2);
			if (strncmp(arp, ARP_PACKET, 2) == 0) {
				memcpy(&arp, pkt + ETHER_FRAME_LEN + 6, 2);
				if (strncmp(arp, ARP_REPLY, 2)  == 0) {
					memcpy(second_fill, fountain_fill, sizeof (char [15]));
					token = strtok(second_fill, ".");
					for (i = 0; i < 4; i++) {
						memset(&seq, 0, 1);
						seq = atoi(token);
						ip_target [i] = seq;
						token = strtok(NULL, ".");
					}
					if (strncmp(ip_target, pkt + ETHER_FRAME_LEN + 14, 4) == 0) {
						memcpy(mac_target, pkt + ETHER_FRAME_LEN + 8, 6);
						printf("mac addresnya adalah :");
						for (i = 0; i < MAC_LEN; i++) {
							printf(" %02x", *(mac_target + i));
						}
						printf("\n");
						break;
					}
				}
			}
		}
	}

	return 0;
}
