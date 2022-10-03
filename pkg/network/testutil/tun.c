#include <fcntl.h>
#include <string.h>

#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>

int create_tap(const char *name) {
    int fd = open("/dev/net/tun", O_RDWR);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_ifrn.ifrn_name, name, IFNAMSIZ);

    int ret = ioctl(fd, TUNSETIFF, &ifr);
    if (ret < 0)
        return ret;

    return fd;
}
