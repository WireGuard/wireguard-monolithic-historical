#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <linux/random.h>

 __attribute__((noreturn)) static void poweroff(void)
{
	ioperm(0x604, 2, 1);
	outw(1 << 13, 0x604);
	sleep(30);
	fprintf(stderr, "\x1b[37m\x1b[41m\x1b[1mFailed to power off!!!\x1b[0m\n");
	exit(1);
}

static void panic(const char *what)
{
	fprintf(stderr, "\n\n\x1b[37m\x1b[41m\x1b[1mSOMETHING WENT HORRIBLY WRONG\x1b[0m\n\n    \x1b[31m\x1b[1m%s: %s\x1b[0m\n\n\x1b[37m\x1b[44m\x1b[1mPower off...\x1b[0m\n\n", what, strerror(errno));
	poweroff();
}

#define pretty_message(msg) puts("\x1b[32m\x1b[1m" msg "\x1b[0m")

int main(int argc, char *argv[])
{
	int status, fd1, fd2, i;
	struct {
		int entropy_count;
		int buffer_size;
		unsigned char buffer[128];
	} entropy = {
		.entropy_count = 128,
		.buffer_size = 128
	};
	pretty_message("[+] Mounting filesystems...");
	mkdir("/dev", 0755);
	mkdir("/proc", 0755);
	mkdir("/sys", 0755);
	mkdir("/tmp", 0755);
	mkdir("/run", 0755);
	mkdir("/var", 0755);
	if (mount("none", "/dev", "devtmpfs", 0, NULL))
		panic("devtmpfs mount");
	if (mount("none", "/proc", "proc", 0, NULL))
		panic("procfs mount");
	if (mount("none", "/sys", "sysfs", 0, NULL))
		panic("sysfs mount");
	if (mount("none", "/tmp", "tmpfs", 0, NULL))
		panic("tmpfs mount");
	if (mount("none", "/run", "tmpfs", 0, NULL))
		panic("tmpfs mount");
	if (symlink("/run", "/var/run"))
		panic("run symlink");
	if (symlink("/proc/self/fd", "/dev/fd"))
		panic("fd symlink");
	pretty_message("[+] Enabling logging...");
	fd1 = open("/proc/sys/kernel/printk", O_WRONLY);
	if (fd1 < 0)
		panic("open(printk)");
	if (write(fd1, "9\n", 2) != 2)
		panic("write(printk)");
	close(fd1);
	pretty_message("[+] Ensuring RNG entropy...");
	fd1 = open("/dev/hwrng", O_RDONLY);
	fd2 = open("/dev/urandom", O_WRONLY);
	if (fd1 < 0 || fd2 < 0)
		panic("open(hwrng,urandom)");
	for (i = 0; i < 4096; ++i) {
		if (read(fd1, entropy.buffer, 128) != 128)
			panic("read(hwrng)");
		if (ioctl(fd2, RNDADDENTROPY, &entropy) < 0)
			panic("ioctl(urandom)");
	}
	close(fd1);
	close(fd2);

	pretty_message("[+] Launching tests...");
	switch (fork()) {
	case -1:
		panic("fork");
		break;
	case 0:
		execl("/init.sh", "init", NULL);
		panic("exec");
		break;
	}
	if (wait(&status) < 0)
		panic("wait");
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		pretty_message("[+] Tests successful! :-)");
		fd1 = open("/dev/vport1p1", O_WRONLY);
		if (fd1 < 0)
			panic("open(vport1p1)");
		if (write(fd1, "success\n", 8) != 8)
			panic("write(success)");
		close(fd1);
	} else
		puts("\x1b[31m\x1b[1m[-] Tests failed! :-(\x1b[0m");
	poweroff();
	return 1;
}
