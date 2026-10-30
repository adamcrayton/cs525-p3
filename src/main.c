/*
 * main.c - the myapp command line (Task 4).
 *
 *   myapp info <address>/<prefix>
 *   myapp split <network>/<prefix> <count>
 *   myapp lookup <table-file> <address>...
 *
 * Exit status:
 *   0  success (and no arguments at all, which prints the usage)
 *   1  bad command line or malformed address/block/count
 *   2  the table file can not be opened or read, or has a bad line
 *   3  an address matched no route
 * A lookup that hits both 1 and 3 reports every address and exits 1.
 */
/*
 * The test build compiles this file too, with -DTEST, and links it with
 * tests/lab-test.c, which has its own main(). Everything here is left out of
 * that build so there is only one main(). (The includes stay outside the
 * guard so the file is never completely empty, which -Wpedantic rejects.)
 */
#include "lab.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifndef TEST

#define PROG "myapp"

enum {
  EXIT_OK = 0,
  EXIT_USAGE = 1,
  EXIT_TABLE = 2,
  EXIT_UNREACHABLE = 3,
};

static const char USAGE[] = "Usage: myapp info <address>/<prefix>\n"
                            "       myapp split <network>/<prefix> <count>\n"
                            "       myapp lookup <table-file> <address>...\n";

/** A bad command line: say what was wrong, show the usage, exit 1. */
static int usage_error(const char *what) {
  fprintf(stderr, PROG ": %s\n%s", what, USAGE);
  return EXIT_USAGE;
}

/**
 * Parse a subnet count: decimal, no sign, no leading zero, fits in uint32_t.
 * Whether it is a power of two is checked by the caller.
 */
static bool parse_count(const char *text, uint32_t *count) {
  uint64_t v = 0;

  if (text[0] == '\0' || (text[0] == '0' && text[1] != '\0')) {
    return false;
  }
  for (const char *p = text; *p != '\0'; p++) {
    if (*p < '0' || *p > '9') {
      return false;
    }
    v = v * 10 + (uint64_t)(*p - '0');
    if (v > UINT32_MAX) {
      return false;
    }
  }
  *count = (uint32_t)v;
  return true;
}

/* ------------------------------------------------------------------------
 * info
 * --------------------------------------------------------------------- */

static int cmd_info(int argc, char *argv[]) {
  cidr_t block;
  char buf[IP_STR_LEN];

  if (argc != 3) {
    return usage_error("info takes exactly one <address>/<prefix>");
  }
  if (!cidr_parse(argv[2], &block)) {
    fprintf(stderr, PROG ": %s: not a valid <address>/<prefix>\n", argv[2]);
    return EXIT_USAGE;
  }

  ip_format(block.addr, buf);
  printf("address    %s\n", buf);
  printf("prefix     /%u\n", (unsigned)block.prefix);
  ip_format(cidr_mask(block.prefix), buf);
  printf("netmask    %s\n", buf);
  ip_format(cidr_network(block), buf);
  printf("network    %s\n", buf);
  ip_format(cidr_broadcast(block), buf);
  printf("broadcast  %s\n", buf);
  ip_format(cidr_first_host(block), buf);
  printf("first host %s\n", buf);
  ip_format(cidr_last_host(block), buf);
  printf("last host  %s\n", buf);
  printf("hosts      %llu\n", (unsigned long long)cidr_host_count(block));
  return EXIT_OK;
}

/* ------------------------------------------------------------------------
 * split
 * --------------------------------------------------------------------- */

static int cmd_split(int argc, char *argv[]) {
  cidr_t block;
  uint32_t count;
  unsigned bits = 0;

  if (argc != 4) {
    return usage_error("split takes a <network>/<prefix> and a <count>");
  }
  if (!cidr_parse(argv[2], &block)) {
    fprintf(stderr, PROG ": %s: not a valid <network>/<prefix>\n", argv[2]);
    return EXIT_USAGE;
  }
  if (!cidr_is_network(block)) {
    char net[CIDR_STR_LEN];
    cidr_t fixed = {cidr_network(block), block.prefix};
    cidr_format(fixed, net);
    fprintf(stderr, PROG ": %s has host bits set, so it is not a network (did you mean %s?)\n",
            argv[2], net);
    return EXIT_USAGE;
  }
  if (!parse_count(argv[3], &count) || count == 0 || (count & (count - 1)) != 0) {
    fprintf(stderr, PROG ": %s: the count must be a power of two (1, 2, 4, 8, ...)\n", argv[3]);
    return EXIT_USAGE;
  }
  while ((UINT32_C(1) << bits) != count) {
    bits++;
  }
  if (block.prefix + bits > 32) {
    fprintf(stderr, PROG ": a /%u can not be split into %s subnets: they would need a /%u\n",
            (unsigned)block.prefix, argv[3], (unsigned)block.prefix + bits);
    return EXIT_USAGE;
  }

  for (uint32_t i = 0; i < count; i++) {
    cidr_t sub;
    char buf[CIDR_STR_LEN];
    if (!cidr_subnet(block, count, i, &sub)) {
      fprintf(stderr, PROG ": could not compute subnet %u\n", (unsigned)i); /* not reached */
      return EXIT_USAGE;
    }
    cidr_format(sub, buf);
    puts(buf);
  }
  return EXIT_OK;
}

/* ------------------------------------------------------------------------
 * lookup
 * --------------------------------------------------------------------- */

static int cmd_lookup(int argc, char *argv[]) {
  const char *path;
  FILE *in;
  fwd_table_t *table;
  size_t bad_line = 0;
  bool malformed = false;
  bool unreachable = false;

  if (argc < 4) {
    return usage_error("lookup takes a <table-file> and at least one <address>");
  }
  path = argv[2];

  in = fopen(path, "r");
  if (in == NULL) {
    fprintf(stderr, PROG ": %s: %s\n", path, strerror(errno));
    return EXIT_TABLE;
  }
  table = table_create();
  if (table == NULL) {
    fclose(in);
    fprintf(stderr, PROG ": out of memory\n");
    return EXIT_TABLE;
  }
  if (!table_load(table, in, &bad_line)) {
    if (bad_line > 0) {
      fprintf(stderr, PROG ": %s:%zu: not a valid route\n", path, bad_line);
    } else {
      fprintf(stderr, PROG ": %s: could not read the file\n", path);
    }
    fclose(in);
    table_destroy(table);
    return EXIT_TABLE;
  }
  fclose(in);

  for (int k = 3; k < argc; k++) {
    uint32_t addr;
    const route_t *route;
    char buf[IP_STR_LEN];

    if (!ip_parse(argv[k], &addr)) {
      fprintf(stderr, PROG ": %s: not a valid address\n", argv[k]);
      malformed = true;
      continue;
    }
    ip_format(addr, buf);
    route = table_lookup(table, addr);
    if (route == NULL) {
      printf("%s unreachable\n", buf);
      unreachable = true;
    } else if (route->gateway != 0) {
      char gw[IP_STR_LEN];
      ip_format(route->gateway, gw);
      printf("%s via %s dev %s\n", buf, gw, route->dev);
    } else {
      printf("%s dev %s\n", buf, route->dev);
    }
  }

  table_destroy(table);
  if (malformed) {
    return EXIT_USAGE;
  }
  return unreachable ? EXIT_UNREACHABLE : EXIT_OK;
}

/* ------------------------------------------------------------------------ */

int main(int argc, char *argv[]) {
  if (argc == 1) {
    fputs(USAGE, stdout); /* asked for help: a clean, successful path */
    return EXIT_OK;
  }
  if (strcmp(argv[1], "info") == 0) {
    return cmd_info(argc, argv);
  }
  if (strcmp(argv[1], "split") == 0) {
    return cmd_split(argc, argv);
  }
  if (strcmp(argv[1], "lookup") == 0) {
    return cmd_lookup(argc, argv);
  }
  fprintf(stderr, PROG ": unknown command '%s'\n%s", argv[1], USAGE);
  return EXIT_USAGE;
}

#endif /* TEST */