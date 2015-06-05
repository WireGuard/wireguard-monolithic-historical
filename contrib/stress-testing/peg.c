#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/limits.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

static unsigned long long interface_tx_bytes(const char *interface)
{
	char buf[PATH_MAX];
	FILE *f;
	unsigned long long ret;
	snprintf(buf, PATH_MAX - 1, "/sys/class/net/%s/statistics/tx_bytes", interface);
	f = fopen(buf, "r");
	fscanf(f, "%llu", &ret);
	fclose(f);
	return ret;
}

int main(int argc, char *argv[])
{
	char buf[1500] = { 0 };
	unsigned long long before, after, i;
	struct timespec begin, end;
	double elapsed;
	struct ifreq req;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(7271),
		.sin_addr = inet_addr(argv[3])
	};
	strcpy(req.ifr_name, argv[1]);
	ioctl(fd, SIOCGIFMTU, &req);

	connect(fd, (struct sockaddr *)&addr, sizeof(addr));

	before = interface_tx_bytes(argv[2]);
	clock_gettime(CLOCK_MONOTONIC, &begin);
	for (i = 0; i < 10000000; ++i)
		send(fd, buf, req.ifr_mtu - 28, 0);
	clock_gettime(CLOCK_MONOTONIC, &end);
	after = interface_tx_bytes(argv[2]);
	elapsed = end.tv_sec - begin.tv_sec + (end.tv_nsec - begin.tv_nsec) / 1000000000.0;

	printf("%.4f mbps\n", ((after - before) * 8) / elapsed / 1000000.0);
	return 0;
}
