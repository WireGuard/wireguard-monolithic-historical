#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/limits.h>

int main(int argc, char *argv[])
{
	static const unsigned char handshake1[143] = { 1, 0 };
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(atoi(argv[2])),
		.sin_addr = inet_addr(argv[1])
	};
	connect(fd, (struct sockaddr *)&addr, sizeof(addr));

	for (;;)
		send(fd, handshake1, sizeof(handshake1), 0);

	close(fd);

	return 0;
}
