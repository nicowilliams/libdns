
all: rfc4408-tests tests

CPPFLAGS += -I/usr/local/libyaml/include -I../src -DDNS_DEBUG=0 -DSPF_DEBUG=1 -DVM_MAXCODE=3182
CFLAGS += -std=gnu99 -g
LDFLAGS += -L/usr/local/libyaml/lib

rfc4408-tests: rfc4408-tests.c ../src/cache.c ../src/zone.c ../src/spf.c ../src/dns.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ -lyaml $(LIBS)

../src/%.c: ../src/%.rl
	ragel -C -o $@ $<

# Tests that link with dns.c
TESTS_LINK = \
	00-spf_xtoi \
	12-segfault-in-dns_res_frame_init \
	14-dns_resconf_search-fqdn \
	15-dns_ai_nextaf-null-deref

# Tests that include dns.c directly (for access to static functions)
TESTS_INCLUDE = \
	20-rr-parse

TESTS = ${TESTS_LINK} ${TESTS_INCLUDE}

00-spf_xtoi: 00-spf_xtoi.c ../src/spf.c
12-segfault-in-dns_res_frame_init: 12-segfault-in-dns_res_frame_init.c
14-dns_resconf_search-fqdn: 14-dns_resconf_search-fqdn.c
15-dns_ai_nextaf-null-deref: 15-dns_ai_nextaf-null-deref.c

${TESTS_LINK}: ../src/dns.c
${TESTS_LINK}:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $@.c ../src/dns.c $(LIBS)

20-rr-parse: 20-rr-parse.c ../src/dns.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

tests: ${TESTS}

check: ${TESTS}
	@for T in ${TESTS}; do ./$$T; done

clean:
	rm -f rfc4408-tests ${TESTS} fpack
	rm -fr *.dSYM

