/*
 * lab.c - IPv4 addresses, CIDR blocks and longest prefix match.
 *
 * Every address is a uint32_t in host byte order (see lab.h).
 */
#define _POSIX_C_SOURCE 200809L /* getline() */

#include "lab.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

#ifdef TEST
/*
 * Test-only fault injection. The tests set this to make the next table
 * allocation fail, so the out-of-memory path in table_add() can be checked.
 * It does not exist in the real program, where lab_realloc is realloc.
 */
bool lab_test_fail_next_alloc = false;

static void *lab_realloc(void *ptr, size_t size) {
  if (lab_test_fail_next_alloc) {
    lab_test_fail_next_alloc = false;
    return NULL;
  }
  return realloc(ptr, size);
}
#else
#define lab_realloc realloc
#endif

/** Prefixes over 32 are treated as 32 everywhere, the way cidr_mask() says. */
static uint8_t clamp_prefix(uint8_t prefix) { return prefix > 32 ? 32 : prefix; }

/**
 * Parse a decimal number of 1 to max_digits digits starting at *p, with no
 * sign and no leading zero (a lone "0" is fine). On success *p is moved past
 * the digits. Nothing after the digits is checked; the caller does that.
 */
static bool parse_decimal(const char **p, unsigned max_digits, unsigned max_value,
                          unsigned *value) {
  const char *s = *p;
  unsigned digits = 0;
  unsigned v = 0;

  while (s[digits] >= '0' && s[digits] <= '9') {
    if (digits == max_digits) {
      return false; /* too many digits */
    }
    v = v * 10 + (unsigned)(s[digits] - '0');
    digits++;
  }
  if (digits == 0) {
    return false; /* empty field, e.g. "1..2.3" or "+1" */
  }
  if (digits > 1 && s[0] == '0') {
    return false; /* leading zero, e.g. "010" */
  }
  if (v > max_value) {
    return false;
  }
  *value = v;
  *p = s + digits;
  return true;
}

/**
 * Parse a dotted quad at the start of text. On success *end points at the
 * first character after the fourth octet, which the caller must check.
 */
static bool parse_quad(const char *text, const char **end, uint32_t *addr) {
  const char *p = text;
  uint32_t result = 0;

  for (int i = 0; i < 4; i++) {
    unsigned octet;
    if (i > 0) {
      if (*p != '.') {
        return false;
      }
      p++;
    }
    if (!parse_decimal(&p, 3, 255, &octet)) {
      return false;
    }
    result = (result << 8) | octet;
  }
  *end = p;
  *addr = result;
  return true;
}

/* ------------------------------------------------------------------------
 * Task 1 - Address parsing and formatting
 * --------------------------------------------------------------------- */

bool ip_parse(const char *text, uint32_t *addr) {
  const char *end;
  uint32_t result;

  if (text == NULL || addr == NULL) {
    return false;
  }
  if (!parse_quad(text, &end, &result) || *end != '\0') {
    return false; /* malformed, or junk after the last octet */
  }
  *addr = result;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN]) {
  if (out == NULL) {
    return;
  }
  snprintf(out, IP_STR_LEN, "%u.%u.%u.%u", (unsigned)(addr >> 24) & 0xFFu,
           (unsigned)(addr >> 16) & 0xFFu, (unsigned)(addr >> 8) & 0xFFu,
           (unsigned)addr & 0xFFu);
}

bool cidr_parse(const char *text, cidr_t *block) {
  const char *p;
  uint32_t addr;
  unsigned prefix;

  if (text == NULL || block == NULL) {
    return false;
  }
  if (!parse_quad(text, &p, &addr) || *p != '/') {
    return false; /* bad address, or the slash is missing */
  }
  p++;
  if (!parse_decimal(&p, 2, 32, &prefix) || *p != '\0') {
    return false; /* missing, too large, leading zero, or trailing junk */
  }
  block->addr = addr;
  block->prefix = (uint8_t)prefix;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN]) {
  uint8_t prefix = clamp_prefix(block.prefix);
  size_t len;

  if (out == NULL) {
    return;
  }
  /* The dotted quad is at most 15 characters, and "/32" at most 3 more, so
   * this always fits in CIDR_STR_LEN. The prefix is written by hand because
   * the compiler can not see that it has at most two digits. */
  ip_format(block.addr, out);
  len = strlen(out);
  out[len++] = '/';
  if (prefix >= 10) {
    out[len++] = (char)('0' + prefix / 10);
  }
  out[len++] = (char)('0' + prefix % 10);
  out[len] = '\0';
}

/* ------------------------------------------------------------------------
 * Task 2 - Subnet arithmetic
 * --------------------------------------------------------------------- */

uint32_t cidr_mask(uint8_t prefix) {
  prefix = clamp_prefix(prefix);
  if (prefix == 0) {
    return 0; /* 0xFFFFFFFF << 32 would be undefined behavior */
  }
  return UINT32_MAX << (32 - prefix);
}

uint32_t cidr_network(cidr_t block) { return block.addr & cidr_mask(block.prefix); }

uint32_t cidr_broadcast(cidr_t block) { return block.addr | ~cidr_mask(block.prefix); }

uint32_t cidr_first_host(cidr_t block) {
  uint32_t network = cidr_network(block);
  return clamp_prefix(block.prefix) >= 31 ? network : network + 1;
}

uint32_t cidr_last_host(cidr_t block) {
  uint32_t broadcast = cidr_broadcast(block);
  return clamp_prefix(block.prefix) >= 31 ? broadcast : broadcast - 1;
}

uint64_t cidr_host_count(cidr_t block) {
  uint8_t prefix = clamp_prefix(block.prefix);
  if (prefix == 32) {
    return 1;
  }
  if (prefix == 31) {
    return 2;
  }
  return (UINT64_C(1) << (32 - prefix)) - 2;
}

bool cidr_contains(cidr_t block, uint32_t addr) {
  uint32_t mask = cidr_mask(block.prefix);
  return (addr & mask) == (block.addr & mask);
}

bool cidr_is_network(cidr_t block) { return (block.addr & ~cidr_mask(block.prefix)) == 0; }

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out) {
  uint8_t prefix = clamp_prefix(block.prefix);
  unsigned bits = 0;
  unsigned new_prefix;

  if (out == NULL || !cidr_is_network(block)) {
    return false;
  }
  if (n == 0 || (n & (n - 1)) != 0) {
    return false; /* not a power of two */
  }
  while ((UINT32_C(1) << bits) != n) {
    bits++; /* bits = log2(n), at most 31 */
  }
  new_prefix = prefix + bits;
  if (new_prefix > 32 || i >= n) {
    return false;
  }
  /*
   * Subnet i starts i subnet-sizes above the network address. The shift is
   * done in 64 bits because i << 32 (n = 1 on a /0) is undefined for 32.
   */
  out->addr = block.addr + (uint32_t)((uint64_t)i << (32 - new_prefix));
  out->prefix = (uint8_t)new_prefix;
  return true;
}

/* ------------------------------------------------------------------------
 * Task 3 - Longest prefix match
 * --------------------------------------------------------------------- */

/**
 * The table is a growable array of routes. Lookup is a linear scan that keeps
 * the longest matching prefix, so insertion order never matters. Destinations
 * are unique (table_add() enforces it), so there is never a tie to break.
 */
struct fwd_table {
  route_t *routes;
  size_t count;
  size_t capacity;
};

/** Space or tab: the field separators in a route line. */
static bool is_blank(char c) { return c == ' ' || c == '\t'; }

/**
 * Copy the next blank-separated field of *p into buf (size bufsize) and move
 * *p past it. Fails if there is no field or it does not fit.
 */
static bool next_field(const char **p, const char *end, char *buf, size_t bufsize) {
  const char *s = *p;
  size_t len = 0;

  while (s < end && is_blank(*s)) {
    s++;
  }
  while (s + len < end && !is_blank(s[len])) {
    len++;
  }
  if (len == 0 || len >= bufsize) {
    return false;
  }
  memcpy(buf, s, len);
  buf[len] = '\0';
  *p = s + len;
  return true;
}

bool route_parse(const char *line, route_t *route) {
  /* Field buffers: one longer than the longest valid field, so overlong
   * fields are caught by next_field() rather than silently truncated. */
  char dest[CIDR_STR_LEN];
  char gw[IP_STR_LEN];
  char dev[DEV_NAME_LEN];
  const char *start;
  const char *end;
  route_t r;

  if (line == NULL || route == NULL) {
    return false;
  }

  /* Trim leading and trailing whitespace, including the newline. */
  start = line;
  while (*start != '\0' && isspace((unsigned char)*start)) {
    start++;
  }
  end = start + strlen(start);
  while (end > start && isspace((unsigned char)end[-1])) {
    end--;
  }

  if (!next_field(&start, end, dest, sizeof dest) ||
      !next_field(&start, end, gw, sizeof gw) ||
      !next_field(&start, end, dev, sizeof dev)) {
    return false;
  }
  if (start != end) {
    return false; /* a fourth field */
  }

  memset(&r, 0, sizeof r);

  if (strcmp(dest, "default") == 0) {
    r.dest.addr = 0;
    r.dest.prefix = 0;
  } else if (!cidr_parse(dest, &r.dest) || !cidr_is_network(r.dest)) {
    return false;
  }

  if (strcmp(gw, "direct") == 0) {
    r.gateway = 0;
  } else if (!ip_parse(gw, &r.gateway)) {
    return false;
  }

  /* The trim and the separators cover spaces and tabs, but a stray '\r' or
   * other control character inside a field would end up in the name. */
  for (const char *c = dev; *c != '\0'; c++) {
    if (!isgraph((unsigned char)*c)) {
      return false;
    }
  }
  memcpy(r.dev, dev, sizeof r.dev);

  *route = r;
  return true;
}

fwd_table_t *table_create(void) {
  return calloc(1, sizeof(fwd_table_t)); /* empty: NULL array, 0 count */
}

void table_destroy(fwd_table_t *table) {
  if (table == NULL) {
    return;
  }
  free(table->routes);
  free(table);
}

size_t table_count(const fwd_table_t *table) { return table == NULL ? 0 : table->count; }

bool table_add(fwd_table_t *table, const route_t *route) {
  route_t copy;

  if (table == NULL || route == NULL || !cidr_is_network(route->dest)) {
    return false;
  }
  for (size_t k = 0; k < table->count; k++) {
    const cidr_t *d = &table->routes[k].dest;
    if (d->addr == route->dest.addr &&
        clamp_prefix(d->prefix) == clamp_prefix(route->dest.prefix)) {
      return false; /* duplicate destination */
    }
  }
  if (table->count == table->capacity) {
    size_t new_capacity = table->capacity == 0 ? 8 : table->capacity * 2;
    route_t *grown = NULL;
    /* Guard the multiplication against overflow; then grown stays NULL. */
    if (new_capacity <= SIZE_MAX / sizeof(route_t)) {
      grown = lab_realloc(table->routes, new_capacity * sizeof(route_t));
    }
    if (grown == NULL) {
      return false; /* out of memory: the old array is unchanged */
    }
    table->routes = grown;
    table->capacity = new_capacity;
  }

  copy = *route;
  copy.dest.prefix = clamp_prefix(copy.dest.prefix);
  copy.dev[DEV_NAME_LEN - 1] = '\0'; /* never trust the caller's terminator */
  table->routes[table->count++] = copy;
  return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line) {
  char *line = NULL;
  size_t cap = 0;
  size_t line_no = 0;
  bool ok = true;

  if (bad_line != NULL) {
    *bad_line = 0;
  }
  if (table == NULL || in == NULL) {
    return false;
  }

  while (getline(&line, &cap, in) != -1) {
    char *hash;
    const char *p;
    route_t route;

    line_no++;
    hash = strchr(line, '#');
    if (hash != NULL) {
      *hash = '\0'; /* drop the comment */
    }
    for (p = line; *p != '\0' && isspace((unsigned char)*p); p++) {
    }
    if (*p == '\0') {
      continue; /* blank once the comment is gone */
    }
    if (!route_parse(line, &route) || !table_add(table, &route)) {
      if (bad_line != NULL) {
        *bad_line = line_no;
      }
      ok = false;
      break;
    }
  }

  if (ok && ferror(in)) {
    ok = false; /* read error; *bad_line stays 0 */
  }
  free(line);
  return ok;
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest) {
  const route_t *best = NULL;

  if (table == NULL) {
    return NULL;
  }
  for (size_t k = 0; k < table->count; k++) {
    const route_t *r = &table->routes[k];
    if (cidr_contains(r->dest, dest) && (best == NULL || r->dest.prefix > best->dest.prefix)) {
      best = r;
    }
  }
  return best;
}