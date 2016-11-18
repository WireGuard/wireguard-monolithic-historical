/* Copyright (C) 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "version.h"
#include "device.h"
#include "noise.h"
#include "packets.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/blake2s.h"
#include "crypto/siphash24.h"
#include "crypto/curve25519.h"

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <net/rtnetlink.h>

static int __init mod_init(void)
{
	int ret = 0;

#ifdef DEBUG
	if (!routing_table_selftest() ||
	    !packet_counter_selftest() ||
	    !curve25519_selftest() ||
	    !chacha20poly1305_selftest() ||
	    !blake2s_selftest() ||
	    !siphash24_selftest())
		return -ENOTRECOVERABLE;
#endif
	chacha20poly1305_init();
	noise_init();

#ifdef CONFIG_WIREGUARD_PARALLEL
	ret = packet_init_data_caches();
	if (ret < 0)
		return ret;
#endif

	ret = device_init();
	if (ret < 0) {
#ifdef CONFIG_WIREGUARD_PARALLEL
		packet_deinit_data_caches();
#endif
		return ret;
	}

	pr_info("WireGuard " WIREGUARD_VERSION " loaded. See www.wireguard.io for information.\n");
	pr_info("Copyright (C) 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.\n");
	return ret;
}

static void __exit mod_exit(void)
{
	device_uninit();
#ifdef CONFIG_WIREGUARD_PARALLEL
	packet_deinit_data_caches();
#endif
	pr_debug("WireGuard has been unloaded\n");
}

module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Simple, secure, and speedy VPN tunnel");
MODULE_AUTHOR("Jason A. Donenfeld <Jason@zx2c4.com>");
MODULE_ALIAS_RTNL_LINK(KBUILD_MODNAME);
