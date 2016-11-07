#ifdef DEBUG
static inline struct in_addr *ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	static struct in_addr ip;
	uint8_t *split = (uint8_t *)&ip;
	split[0] = a;
	split[1] = b;
	split[2] = c;
	split[3] = d;
	return &ip;
}
static inline struct in6_addr *ip6(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
	static struct in6_addr ip;
	__be32 *split = (__be32 *)&ip;
	split[0] = cpu_to_be32(a);
	split[1] = cpu_to_be32(b);
	split[2] = cpu_to_be32(c);
	split[3] = cpu_to_be32(d);
	return &ip;
}

bool routing_table_selftest(void)
{
	struct routing_table t;
	struct wireguard_peer *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL, *f = NULL, *g = NULL, *h = NULL;
	size_t i = 0;
	bool success = false;
	struct in6_addr ip;
	__be64 part;

	routing_table_init(&t);
#define init_peer(name) do { name = kzalloc(sizeof(struct wireguard_peer), GFP_KERNEL); if (!name) goto free; kref_init(&name->refcount); } while (0)
	init_peer(a);
	init_peer(b);
	init_peer(c);
	init_peer(d);
	init_peer(e);
	init_peer(f);
	init_peer(g);
	init_peer(h);
#undef init_peer

#define insert(version, mem, ipa, ipb, ipc, ipd, cidr) routing_table_insert_v##version(&t, ip##version(ipa, ipb, ipc, ipd), cidr, mem)
	insert(4, a, 192, 168, 4, 0, 24);
	insert(4, b, 192, 168, 4, 4, 32);
	insert(4, c, 192, 168, 0, 0, 16);
	insert(4, d, 192, 95, 5, 64, 27);
	insert(4, c, 192, 95, 5, 65, 27); /* replaces previous entry, and maskself is required */
	insert(6, d, 0x26075300, 0x60006b00, 0, 0xc05f0543, 128);
	insert(6, c, 0x26075300, 0x60006b00, 0, 0, 64);
	insert(4, e, 0, 0, 0, 0, 0);
	insert(6, e, 0, 0, 0, 0, 0);
	insert(6, f, 0, 0, 0, 0, 0); /* replaces previous entry */
	insert(6, g, 0x24046800, 0, 0, 0, 32);
	insert(6, h, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef, 64); /* maskself is required */
	insert(6, a, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef, 128);
	insert(4, g, 64, 15, 112, 0, 20);
	insert(4, h, 64, 15, 123, 211, 25); /* maskself is required */
	insert(4, a, 10, 0, 0, 0, 25);
	insert(4, b, 10, 0, 0, 128, 25);
	insert(4, a, 10, 1, 0, 0, 30);
	insert(4, b, 10, 1, 0, 4, 30);
	insert(4, c, 10, 1, 0, 8, 29);
	insert(4, d, 10, 1, 0, 16, 29);
#undef insert

	success = true;
#define test(version, mem, ipa, ipb, ipc, ipd) do { \
	bool _s = routing_table_lookup_v##version(&t, ip##version(ipa, ipb, ipc, ipd)) == mem; \
	++i; \
	if (!_s) { \
		pr_info("routing table self-test %zu: FAIL\n", i); \
		success = false; \
	} \
} while (0)
	test(4, a, 192, 168, 4, 20);
	test(4, a, 192, 168, 4, 0);
	test(4, b, 192, 168, 4, 4);
	test(4, c, 192, 168, 200, 182);
	test(4, c, 192, 95, 5, 68);
	test(4, e, 192, 95, 5, 96);
	test(6, d, 0x26075300, 0x60006b00, 0, 0xc05f0543);
	test(6, c, 0x26075300, 0x60006b00, 0, 0xc02e01ee);
	test(6, f, 0x26075300, 0x60006b01, 0, 0);
	test(6, g, 0x24046800, 0x40040806, 0, 0x1006);
	test(6, g, 0x24046800, 0x40040806, 0x1234, 0x5678);
	test(6, f, 0x240467ff, 0x40040806, 0x1234, 0x5678);
	test(6, f, 0x24046801, 0x40040806, 0x1234, 0x5678);
	test(6, h, 0x24046800, 0x40040800, 0x1234, 0x5678);
	test(6, h, 0x24046800, 0x40040800, 0, 0);
	test(6, h, 0x24046800, 0x40040800, 0x10101010, 0x10101010);
	test(6, a, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef);
	test(4, g, 64, 15, 116, 26);
	test(4, g, 64, 15, 127, 3);
	test(4, g, 64, 15, 123, 1);
	test(4, h, 64, 15, 123, 128);
	test(4, h, 64, 15, 123, 129);
	test(4, a, 10, 0, 0, 52);
	test(4, b, 10, 0, 0, 220);
	test(4, a, 10, 1, 0, 2);
	test(4, b, 10, 1, 0, 6);
	test(4, c, 10, 1, 0, 10);
	test(4, d, 10, 1, 0, 20);
#undef test

	/* These will hit the BUG_ON(len >= 128) in free_node if something goes wrong. */
	for (i = 0; i < 128; ++i) {
		part = cpu_to_be64(~(1LLU << (i % 64)));
		memset(&ip, 0xff, 16);
		memcpy((uint8_t *)&ip + (i < 64) * 8, &part, 8);
		routing_table_insert_v6(&t, &ip, 128, a);
	}

	if (success)
		pr_info("routing table self-tests: pass\n");

free:
	routing_table_free(&t);
	kfree(a);
	kfree(b);
	kfree(c);
	kfree(d);
	kfree(e);
	kfree(f);
	kfree(g);
	kfree(h);

	return success;
}
#endif
