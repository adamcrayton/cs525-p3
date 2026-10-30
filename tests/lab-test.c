#define _POSIX_C_SOURCE 200809L /* fmemopen() */

#include "harness/unity.h"
#include "../src/lab.h"

#include <string.h>

#define IP(a, b, c, d) \
  ((uint32_t)(a) << 24 | (uint32_t)(b) << 16 | (uint32_t)(c) << 8 | (uint32_t)(d))

static fwd_table_t *table;

void setUp(void) { table = table_create(); }

void tearDown(void) {
  table_destroy(table);
  table = NULL;
}

/* Build a block from text, failing the test if it does not parse. */
static cidr_t blk(const char *text) {
  cidr_t b = {0, 0};
  TEST_ASSERT_TRUE_MESSAGE(cidr_parse(text, &b), text);
  return b;
}

/* Parse a route line and add it, failing the test if either step fails. */
static void add(const char *line) {
  route_t r;
  TEST_ASSERT_TRUE_MESSAGE(route_parse(line, &r), line);
  TEST_ASSERT_TRUE_MESSAGE(table_add(table, &r), line);
}

/* Load a whole table file held in a string. */
static bool load(const char *text, size_t *bad_line) {
  FILE *f = fmemopen((void *)text, strlen(text), "r");
  bool ok;
  TEST_ASSERT_NOT_NULL(f);
  ok = table_load(table, f, bad_line);
  fclose(f);
  return ok;
}

/* ------------------------------------------------------------------------
 * Task 1
 * --------------------------------------------------------------------- */

void test_ip_parse_valid(void) {
  uint32_t a = 0;
  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &a));
  TEST_ASSERT_EQUAL_HEX32(0xC0A8010A, a);
  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &a));
  TEST_ASSERT_EQUAL_HEX32(0, a);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &a));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, a);
  TEST_ASSERT_TRUE(ip_parse("10.0.100.1", &a));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 100, 1), a);
}

void test_ip_parse_rejects_handout_cases(void) {
  const char *bad[] = {"1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1", "010.0.0.1", "1.2.3.4x"};
  for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++) {
    uint32_t a = 0xDEADBEEF;
    TEST_ASSERT_FALSE_MESSAGE(ip_parse(bad[k], &a), bad[k]);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0xDEADBEEF, a, "addr must be untouched on failure");
  }
}

void test_ip_parse_rejects_more(void) {
  const char *bad[] = {"",        "+1.2.3.4", "-1.2.3.4",  " 1.2.3.4", "1.2.3.4 ",
                       "1.2.3.4\n", ".1.2.3",  "1.2.3.",    "1.2.3.4.", "1.2.3.00",
                       "1.2.3.0001", "1.2.3.1000", "4294967295", "0x1.2.3.4", "1,2,3,4",
                       "a.b.c.d", "1.2.3.4/24", "999.0.0.0"};
  for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++) {
    uint32_t a = 7;
    TEST_ASSERT_FALSE_MESSAGE(ip_parse(bad[k], &a), bad[k]);
    TEST_ASSERT_EQUAL_UINT32(7, a);
  }
  TEST_ASSERT_FALSE(ip_parse(NULL, &(uint32_t){0}));
}

void test_ip_format(void) {
  char buf[IP_STR_LEN];
  ip_format(0xC0A8010A, buf);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", buf);
  ip_format(0, buf);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", buf);
  ip_format(0xFFFFFFFF, buf);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", buf);
}

void test_ip_round_trip(void) {
  const char *good[] = {"1.2.3.4", "132.178.227.11", "10.0.0.255", "172.16.254.1"};
  for (size_t k = 0; k < sizeof good / sizeof good[0]; k++) {
    uint32_t a;
    char buf[IP_STR_LEN];
    TEST_ASSERT_TRUE(ip_parse(good[k], &a));
    ip_format(a, buf);
    TEST_ASSERT_EQUAL_STRING(good[k], buf);
  }
}

void test_cidr_parse_valid(void) {
  cidr_t b;
  TEST_ASSERT_TRUE(cidr_parse("192.168.1.0/24", &b));
  TEST_ASSERT_EQUAL_HEX32(IP(192, 168, 1, 0), b.addr);
  TEST_ASSERT_EQUAL_UINT8(24, b.prefix);

  /* host bits are allowed */
  TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &b));
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 11), b.addr);
  TEST_ASSERT_EQUAL_UINT8(25, b.prefix);

  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &b));
  TEST_ASSERT_EQUAL_UINT8(0, b.prefix);
  TEST_ASSERT_TRUE(cidr_parse("1.2.3.4/32", &b));
  TEST_ASSERT_EQUAL_UINT8(32, b.prefix);
}

void test_cidr_parse_rejects(void) {
  const char *bad[] = {"1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/", "1.2.3/24", "1.2.3.4",
                       "1.2.3.4/00", "1.2.3.4/-1", "1.2.3.4/+8", "1.2.3.4/8x", "1.2.3.4/ 8",
                       "1.2.3.4 /8", "1.2.3.4//8", "1.2.3.4/8/8", "010.0.0.0/8", "/8",
                       "1.2.3.4/100", "1.2.3.4/8\n"};
  for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++) {
    cidr_t b = {0x1234, 7};
    TEST_ASSERT_FALSE_MESSAGE(cidr_parse(bad[k], &b), bad[k]);
    TEST_ASSERT_EQUAL_HEX32(0x1234, b.addr);
    TEST_ASSERT_EQUAL_UINT8(7, b.prefix);
  }
  TEST_ASSERT_FALSE(cidr_parse(NULL, &(cidr_t){0, 0}));
}

void test_cidr_format(void) {
  char buf[CIDR_STR_LEN];
  cidr_format((cidr_t){IP(132, 178, 227, 11), 25}, buf);
  TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", buf); /* address exactly as stored */
  cidr_format((cidr_t){0xFFFFFFFF, 32}, buf);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", buf);
  cidr_format((cidr_t){0, 0}, buf);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0/0", buf);
  cidr_format((cidr_t){IP(10, 0, 0, 1), 200}, buf);
  TEST_ASSERT_EQUAL_STRING("10.0.0.1/32", buf);
}

/* ------------------------------------------------------------------------
 * Task 2
 * --------------------------------------------------------------------- */

void test_cidr_mask(void) {
  TEST_ASSERT_EQUAL_HEX32(0x00000000, cidr_mask(0));
  TEST_ASSERT_EQUAL_HEX32(0x80000000, cidr_mask(1));
  TEST_ASSERT_EQUAL_HEX32(0xFF000000, cidr_mask(8));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFF00, cidr_mask(24));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFF80, cidr_mask(25));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFE, cidr_mask(31));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(32));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(33));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(255));
}

void test_onyx_worksheet(void) {
  cidr_t b = blk("132.178.227.11/25");
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 0), cidr_network(b));
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 127), cidr_broadcast(b));
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 1), cidr_first_host(b));
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 126), cidr_last_host(b));
  TEST_ASSERT_EQUAL_UINT64(126, cidr_host_count(b));
  TEST_ASSERT_TRUE(cidr_contains(b, IP(132, 178, 227, 50)));
  TEST_ASSERT_FALSE(cidr_contains(b, IP(132, 178, 227, 200)));
  TEST_ASSERT_FALSE(cidr_is_network(b));
}

void test_slash_24(void) {
  cidr_t b = blk("192.168.1.0/24");
  TEST_ASSERT_TRUE(cidr_is_network(b));
  TEST_ASSERT_EQUAL_HEX32(IP(192, 168, 1, 255), cidr_broadcast(b));
  TEST_ASSERT_EQUAL_UINT64(254, cidr_host_count(b));
}

void test_slash_30(void) {
  cidr_t b = blk("10.0.0.4/30");
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 5), cidr_first_host(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 6), cidr_last_host(b));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(b));
}

void test_slash_31(void) {
  cidr_t b = blk("10.0.0.7/31");
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 6), cidr_network(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 7), cidr_broadcast(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 6), cidr_first_host(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 7), cidr_last_host(b));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(b));
}

void test_slash_32(void) {
  cidr_t b = blk("10.1.2.3/32");
  TEST_ASSERT_TRUE(cidr_is_network(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 1, 2, 3), cidr_network(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 1, 2, 3), cidr_broadcast(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 1, 2, 3), cidr_first_host(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 1, 2, 3), cidr_last_host(b));
  TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(b));
  TEST_ASSERT_TRUE(cidr_contains(b, IP(10, 1, 2, 3)));
  TEST_ASSERT_FALSE(cidr_contains(b, IP(10, 1, 2, 4)));
}

void test_slash_0(void) {
  cidr_t b = blk("0.0.0.0/0");
  TEST_ASSERT_EQUAL_HEX32(0, cidr_network(b));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_broadcast(b));
  TEST_ASSERT_EQUAL_HEX32(1, cidr_first_host(b));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFE, cidr_last_host(b));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(4294967294), cidr_host_count(b));
  TEST_ASSERT_TRUE(cidr_contains(b, 0));
  TEST_ASSERT_TRUE(cidr_contains(b, 0xFFFFFFFF));
  TEST_ASSERT_TRUE(cidr_is_network(b));
  /* any address with prefix 0 is still the whole space */
  TEST_ASSERT_FALSE(cidr_is_network((cidr_t){IP(1, 2, 3, 4), 0}));
  TEST_ASSERT_TRUE(cidr_contains((cidr_t){IP(1, 2, 3, 4), 0}, IP(200, 0, 0, 1)));
}

void test_slash_1(void) {
  cidr_t b = blk("128.0.0.0/1");
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(2147483646), cidr_host_count(b));
  TEST_ASSERT_TRUE(cidr_contains(b, IP(200, 1, 1, 1)));
  TEST_ASSERT_FALSE(cidr_contains(b, IP(127, 255, 255, 255)));
}

void test_prefix_over_32_is_32(void) {
  cidr_t b = {IP(10, 0, 0, 1), 40};
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 1), cidr_network(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 1), cidr_broadcast(b));
  TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 1), cidr_first_host(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 1), cidr_last_host(b));
}

void test_cidr_subnet_quarters(void) {
  cidr_t parent = blk("192.168.1.0/24");
  const char *want[] = {"192.168.1.0/26", "192.168.1.64/26", "192.168.1.128/26",
                        "192.168.1.192/26"};
  for (uint32_t i = 0; i < 4; i++) {
    cidr_t s;
    char buf[CIDR_STR_LEN];
    TEST_ASSERT_TRUE(cidr_subnet(parent, 4, i, &s));
    cidr_format(s, buf);
    TEST_ASSERT_EQUAL_STRING(want[i], buf);
  }
}

void test_cidr_subnet_edges(void) {
  cidr_t s;
  char buf[CIDR_STR_LEN];

  /* n = 1 is the block itself, even for /0 (no shift by 32) */
  TEST_ASSERT_TRUE(cidr_subnet(blk("0.0.0.0/0"), 1, 0, &s));
  cidr_format(s, buf);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0/0", buf);

  /* /0 into halves */
  TEST_ASSERT_TRUE(cidr_subnet(blk("0.0.0.0/0"), 2, 1, &s));
  cidr_format(s, buf);
  TEST_ASSERT_EQUAL_STRING("128.0.0.0/1", buf);

  /* /0 into 2^31 /31s: the last one */
  TEST_ASSERT_TRUE(cidr_subnet(blk("0.0.0.0/0"), UINT32_C(0x80000000), UINT32_C(0x7FFFFFFF), &s));
  cidr_format(s, buf);
  TEST_ASSERT_EQUAL_STRING("255.255.255.254/31", buf);

  /* /30 into four /32s */
  TEST_ASSERT_TRUE(cidr_subnet(blk("10.0.0.4/30"), 4, 3, &s));
  cidr_format(s, buf);
  TEST_ASSERT_EQUAL_STRING("10.0.0.7/32", buf);

  /* /32 into one */
  TEST_ASSERT_TRUE(cidr_subnet(blk("10.0.0.7/32"), 1, 0, &s));
}

void test_cidr_subnet_failures(void) {
  cidr_t s = {0xABCD, 9};
  cidr_t net = blk("192.168.1.0/24");

  TEST_ASSERT_FALSE(cidr_subnet(net, 4, 0, NULL));
  TEST_ASSERT_FALSE(cidr_subnet(blk("192.168.1.5/24"), 4, 0, &s)); /* not a network */
  TEST_ASSERT_FALSE(cidr_subnet(net, 0, 0, &s));
  TEST_ASSERT_FALSE(cidr_subnet(net, 3, 0, &s));
  TEST_ASSERT_FALSE(cidr_subnet(net, 6, 0, &s));
  TEST_ASSERT_FALSE(cidr_subnet(net, 512, 0, &s)); /* would be /33 */
  TEST_ASSERT_FALSE(cidr_subnet(net, 4, 4, &s));   /* i out of range */
  TEST_ASSERT_FALSE(cidr_subnet(blk("10.0.0.7/32"), 2, 0, &s));
  TEST_ASSERT_FALSE(cidr_subnet(blk("0.0.0.0/0"), UINT32_C(0x80000000), UINT32_C(0x80000000), &s));
  TEST_ASSERT_EQUAL_HEX32(0xABCD, s.addr);
  TEST_ASSERT_EQUAL_UINT8(9, s.prefix);
}

/* ------------------------------------------------------------------------
 * Task 3
 * --------------------------------------------------------------------- */

void test_route_parse_valid(void) {
  route_t r;
  TEST_ASSERT_TRUE(route_parse("10.1.0.0/16 192.168.0.1 eth1", &r));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 1, 0, 0), r.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(16, r.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(IP(192, 168, 0, 1), r.gateway);
  TEST_ASSERT_EQUAL_STRING("eth1", r.dev);

  TEST_ASSERT_TRUE(route_parse("default 132.178.227.1 eth0\n", &r));
  TEST_ASSERT_EQUAL_HEX32(0, r.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(0, r.dest.prefix);

  TEST_ASSERT_TRUE(route_parse("  \t192.168.1.0/24\t\tdirect   wlan0  \r\n", &r));
  TEST_ASSERT_EQUAL_HEX32(0, r.gateway);
  TEST_ASSERT_EQUAL_STRING("wlan0", r.dev);

  TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 direct abcdefghijklmno", &r)); /* 15 chars */
  TEST_ASSERT_EQUAL_STRING("abcdefghijklmno", r.dev);
}

void test_route_parse_rejects(void) {
  const char *bad[] = {
      "",
      "   \n",
      "10.0.0.0/8 direct",                       /* two fields */
      "10.0.0.0/8",                              /* one field */
      "10.0.0.0/8 direct eth0 extra",            /* four fields */
      "10.0.0.1/8 direct eth0",                  /* host bits set */
      "10.0.0.0 direct eth0",                    /* no prefix */
      "10.0.0.0/33 direct eth0",                 /* bad prefix */
      "10.0.0.0/8 10.0.0 eth0",                  /* bad gateway */
      "10.0.0.0/8 010.0.0.1 eth0",               /* octal-looking gateway */
      "10.0.0.0/8 direct abcdefghijklmnop",      /* 16 chars: too long */
      "Default direct eth0",                     /* keywords are exact */
      "default Direct eth0",
      "10.0.0.0/8 direct eth0 # comment",        /* comments are not handled here */
      "10.0.0.0/8,direct,eth0",
  };
  for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++) {
    route_t r;
    memset(&r, 0x5A, sizeof r);
    TEST_ASSERT_FALSE_MESSAGE(route_parse(bad[k], &r), bad[k]);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0x5A5A5A5A, r.gateway, "route must be untouched");
  }
  TEST_ASSERT_FALSE(route_parse(NULL, &(route_t){0}));
}

void test_table_basics(void) {
  route_t r;
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  TEST_ASSERT_EQUAL_size_t(0, table_count(NULL));
  TEST_ASSERT_NULL(table_lookup(table, IP(1, 2, 3, 4)));
  TEST_ASSERT_NULL(table_lookup(NULL, IP(1, 2, 3, 4)));
  table_destroy(NULL);

  TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 direct eth0", &r));
  TEST_ASSERT_FALSE(table_add(NULL, &r));
  TEST_ASSERT_FALSE(table_add(table, NULL));
  TEST_ASSERT_TRUE(table_add(table, &r));
  TEST_ASSERT_FALSE(table_add(table, &r)); /* duplicate */
  TEST_ASSERT_EQUAL_size_t(1, table_count(table));

  /* same block, different gateway: still a duplicate */
  TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 1.1.1.1 eth9", &r));
  TEST_ASSERT_FALSE(table_add(table, &r));

  /* same address, different prefix: a different block */
  TEST_ASSERT_TRUE(route_parse("10.0.0.0/16 direct eth0", &r));
  TEST_ASSERT_TRUE(table_add(table, &r));

  /* host bits set */
  r.dest = (cidr_t){IP(10, 0, 0, 1), 8};
  TEST_ASSERT_FALSE(table_add(table, &r));
  TEST_ASSERT_EQUAL_size_t(2, table_count(table));
}

void test_table_add_copies(void) {
  route_t r;
  const route_t *found;
  TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 direct eth0", &r));
  TEST_ASSERT_TRUE(table_add(table, &r));
  strcpy(r.dev, "changed");
  found = table_lookup(table, IP(10, 9, 9, 9));
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_STRING("eth0", found->dev);
}

void test_lookup_handout_example(void) {
  const route_t *r;
  add("10.0.0.0/8 1.1.1.8 eth8");
  add("10.1.0.0/16 1.1.1.16 eth16");
  add("10.1.2.0/24 1.1.1.24 eth24");
  add("10.1.2.128/25 1.1.1.25 eth25");

  r = table_lookup(table, IP(10, 1, 2, 200));
  TEST_ASSERT_NOT_NULL(r);
  TEST_ASSERT_EQUAL_STRING("eth25", r->dev);

  TEST_ASSERT_EQUAL_STRING("eth24", table_lookup(table, IP(10, 1, 2, 100))->dev);
  TEST_ASSERT_EQUAL_STRING("eth16", table_lookup(table, IP(10, 1, 3, 1))->dev);
  TEST_ASSERT_EQUAL_STRING("eth8", table_lookup(table, IP(10, 200, 0, 1))->dev);
  TEST_ASSERT_NULL(table_lookup(table, IP(11, 0, 0, 1))); /* no default route */
}

void test_lookup_order_does_not_matter(void) {
  add("10.1.2.128/25 1.1.1.25 eth25");
  add("default 9.9.9.9 eth0");
  add("10.1.0.0/16 1.1.1.16 eth16");
  add("10.0.0.0/8 1.1.1.8 eth8");
  add("10.1.2.0/24 1.1.1.24 eth24");

  TEST_ASSERT_EQUAL_STRING("eth25", table_lookup(table, IP(10, 1, 2, 200))->dev);
  TEST_ASSERT_EQUAL_STRING("eth24", table_lookup(table, IP(10, 1, 2, 1))->dev);
}

void test_lookup_default_is_last_resort(void) {
  add("default 132.178.227.1 eth0");
  add("132.178.227.0/25 direct eth0");
  add("192.168.0.0/16 10.0.0.1 eth1");

  TEST_ASSERT_EQUAL_HEX32(0, table_lookup(table, IP(132, 178, 227, 50))->gateway);
  TEST_ASSERT_EQUAL_STRING("eth1", table_lookup(table, IP(192, 168, 9, 9))->dev);
  TEST_ASSERT_EQUAL_UINT8(0, table_lookup(table, IP(8, 8, 8, 8))->dest.prefix);
  TEST_ASSERT_EQUAL_UINT8(0, table_lookup(table, IP(132, 178, 227, 200))->dest.prefix);
  TEST_ASSERT_EQUAL_UINT8(0, table_lookup(table, 0xFFFFFFFF)->dest.prefix);
}

void test_lookup_host_route(void) {
  add("10.0.0.0/8 direct eth0");
  add("10.5.5.5/32 10.0.0.1 tun0");
  TEST_ASSERT_EQUAL_STRING("tun0", table_lookup(table, IP(10, 5, 5, 5))->dev);
  TEST_ASSERT_EQUAL_STRING("eth0", table_lookup(table, IP(10, 5, 5, 6))->dev);
}

void test_table_grows(void) {
  char line[64];
  for (int k = 0; k < 1000; k++) {
    snprintf(line, sizeof line, "10.%d.%d.0/24 direct eth%d", k / 256, k % 256, k % 10);
    add(line);
  }
  TEST_ASSERT_EQUAL_size_t(1000, table_count(table));
  TEST_ASSERT_EQUAL_STRING("eth9", table_lookup(table, IP(10, 3, 231, 77))->dev); /* k = 999 */
}

void test_table_load_good(void) {
  size_t bad = 99;
  const char *text = "# a forwarding table\n"
                     "\n"
                     "default        132.178.227.1  eth0   # last resort\n"
                     "132.178.227.0/25 direct       eth0\n"
                     "   \t  # an indented comment\n"
                     "10.0.0.0/8     192.168.0.1    eth1\n"
                     "10.1.2.0/24    192.168.0.2    eth2"; /* no final newline */
  TEST_ASSERT_TRUE(load(text, &bad));
  TEST_ASSERT_EQUAL_size_t(0, bad);
  TEST_ASSERT_EQUAL_size_t(4, table_count(table));
  TEST_ASSERT_EQUAL_STRING("eth2", table_lookup(table, IP(10, 1, 2, 3))->dev);
}

void test_table_load_bad_line(void) {
  size_t bad = 0;
  const char *text = "10.0.0.0/8 direct eth0\n"
                     "# fine\n"
                     "10.1.0.0/16 direct eth1\n"
                     "10.1.2.3/24 direct eth2\n" /* line 4: host bits */
                     "10.2.0.0/16 direct eth3\n";
  TEST_ASSERT_FALSE(load(text, &bad));
  TEST_ASSERT_EQUAL_size_t(4, bad);
  TEST_ASSERT_EQUAL_size_t(2, table_count(table)); /* earlier routes stay */
}

void test_table_load_duplicate(void) {
  size_t bad = 0;
  TEST_ASSERT_FALSE(load("10.0.0.0/8 direct eth0\n10.0.0.0/8 1.2.3.4 eth1\n", &bad));
  TEST_ASSERT_EQUAL_size_t(2, bad);
  TEST_ASSERT_EQUAL_size_t(1, table_count(table));
}

void test_table_load_nulls(void) {
  size_t bad = 42;
  FILE *f = fmemopen((void *)"x", 1, "r");
  TEST_ASSERT_FALSE(table_load(NULL, f, &bad));
  TEST_ASSERT_EQUAL_size_t(0, bad);
  bad = 42;
  TEST_ASSERT_FALSE(table_load(table, NULL, &bad));
  TEST_ASSERT_EQUAL_size_t(0, bad);
  TEST_ASSERT_FALSE(table_load(table, NULL, NULL));
  fclose(f);

  TEST_ASSERT_TRUE(load("", NULL)); /* empty file is fine */
  TEST_ASSERT_FALSE(load("garbage\n", NULL));
}

void test_format_null_buffer(void) {
  /* Nothing to check except that these return without crashing. */
  ip_format(IP(1, 2, 3, 4), NULL);
  cidr_format((cidr_t){IP(1, 2, 3, 4), 8}, NULL);
}

void test_route_parse_rejects_control_chars_in_dev(void) {
  route_t r;
  /* Fields split only on spaces and tabs, so these stay inside the name. */
  TEST_ASSERT_FALSE(route_parse("10.0.0.0/8 direct eth\x01" "0", &r));
  TEST_ASSERT_FALSE(route_parse("10.0.0.0/8 direct eth\r0", &r));
  TEST_ASSERT_FALSE(route_parse("10.0.0.0/8 direct eth\v0", &r));
}

void test_table_load_read_error(void) {
  /* On Linux a directory opens for reading but every read fails (EISDIR),
   * which is a read error rather than a bad line. */
  size_t bad = 42;
  FILE *f = fopen(".", "r");
  TEST_ASSERT_NOT_NULL(f);
  TEST_ASSERT_FALSE(table_load(table, f, &bad));
  TEST_ASSERT_EQUAL_size_t(0, bad);
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  fclose(f);
}

/* Defined in lab.c when it is built with -DTEST; see lab_realloc() there. */
extern bool lab_test_fail_next_alloc;

void test_table_add_out_of_memory(void) {
  char line[64];
  route_t r;

  /* The first add allocates room for 8; fill it so the 9th must grow. */
  for (int k = 0; k < 8; k++) {
    snprintf(line, sizeof line, "10.0.%d.0/24 direct eth%d", k, k);
    add(line);
  }
  TEST_ASSERT_TRUE(route_parse("10.0.8.0/24 direct eth8", &r));

  lab_test_fail_next_alloc = true;
  TEST_ASSERT_FALSE(table_add(table, &r));
  TEST_ASSERT_FALSE(lab_test_fail_next_alloc); /* the failure was used */

  /* Unchanged on failure: same count, old routes still there. */
  TEST_ASSERT_EQUAL_size_t(8, table_count(table));
  TEST_ASSERT_NULL(table_lookup(table, IP(10, 0, 8, 1)));
  TEST_ASSERT_EQUAL_STRING("eth7", table_lookup(table, IP(10, 0, 7, 1))->dev);

  /* And it recovers once memory is available again. */
  TEST_ASSERT_TRUE(table_add(table, &r));
  TEST_ASSERT_EQUAL_size_t(9, table_count(table));
  TEST_ASSERT_EQUAL_STRING("eth8", table_lookup(table, IP(10, 0, 8, 1))->dev);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_valid);
  RUN_TEST(test_ip_parse_rejects_handout_cases);
  RUN_TEST(test_ip_parse_rejects_more);
  RUN_TEST(test_ip_format);
  RUN_TEST(test_ip_round_trip);
  RUN_TEST(test_cidr_parse_valid);
  RUN_TEST(test_cidr_parse_rejects);
  RUN_TEST(test_cidr_format);
  RUN_TEST(test_cidr_mask);
  RUN_TEST(test_onyx_worksheet);
  RUN_TEST(test_slash_24);
  RUN_TEST(test_slash_30);
  RUN_TEST(test_slash_31);
  RUN_TEST(test_slash_32);
  RUN_TEST(test_slash_0);
  RUN_TEST(test_slash_1);
  RUN_TEST(test_prefix_over_32_is_32);
  RUN_TEST(test_cidr_subnet_quarters);
  RUN_TEST(test_cidr_subnet_edges);
  RUN_TEST(test_cidr_subnet_failures);
  RUN_TEST(test_route_parse_valid);
  RUN_TEST(test_route_parse_rejects);
  RUN_TEST(test_table_basics);
  RUN_TEST(test_table_add_copies);
  RUN_TEST(test_lookup_handout_example);
  RUN_TEST(test_lookup_order_does_not_matter);
  RUN_TEST(test_lookup_default_is_last_resort);
  RUN_TEST(test_lookup_host_route);
  RUN_TEST(test_table_grows);
  RUN_TEST(test_table_load_good);
  RUN_TEST(test_table_load_bad_line);
  RUN_TEST(test_table_load_duplicate);
  RUN_TEST(test_table_load_nulls);
  RUN_TEST(test_format_null_buffer);
  RUN_TEST(test_route_parse_rejects_control_chars_in_dev);
  RUN_TEST(test_table_load_read_error);
  RUN_TEST(test_table_add_out_of_memory);
  return UNITY_END();
}