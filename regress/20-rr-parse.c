/*
 * Test parsing of modern DNS RR types:
 * CAA, URI, TLSA, SVCB, HTTPS, DNSKEY, DS, RRSIG, NSEC, NSEC3
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>

#include "dns.c"

static int test_count = 0;
static int fail_count = 0;

#define TEST_START(name) do { \
	test_count++; \
	fprintf(stderr, "  testing %s... ", name); \
} while (0)

#define TEST_OK() do { \
	fprintf(stderr, "OK\n"); \
} while (0)

#define TEST_FAIL(fmt, ...) do { \
	fprintf(stderr, "FAILED: " fmt "\n", ##__VA_ARGS__); \
	fail_count++; \
} while (0)

/*
 * Helper to build a minimal DNS packet with one answer RR
 */
static struct dns_packet *make_packet(const unsigned char *rdata, size_t rdlen,
                                       uint16_t type, const char *name) {
	struct dns_packet *P;
	unsigned char *p;
	size_t namelen;

	P = dns_p_make(512, NULL);
	if (!P)
		return NULL;

	/* DNS header - 12 bytes */
	p = P->data;
	memset(p, 0, 12);
	p[2] = 0x81; p[3] = 0x80; /* QR=1, RD=1, RA=1 */
	p[4] = 0x00; p[5] = 0x01; /* QDCOUNT=1 */
	p[6] = 0x00; p[7] = 0x01; /* ANCOUNT=1 */
	p += 12;

	/* Question section - encode name */
	namelen = 0;
	const char *label = name;
	while (*label) {
		const char *dot = strchr(label, '.');
		size_t llen = dot ? (size_t)(dot - label) : strlen(label);
		*p++ = (unsigned char)llen;
		memcpy(p, label, llen);
		p += llen;
		namelen += 1 + llen;
		if (dot)
			label = dot + 1;
		else
			break;
	}
	*p++ = 0; /* root label */
	namelen++;

	/* QTYPE and QCLASS */
	*p++ = (type >> 8) & 0xff;
	*p++ = type & 0xff;
	*p++ = 0x00; *p++ = 0x01; /* IN */

	/* Answer section - use compression pointer to question name */
	*p++ = 0xc0; *p++ = 0x0c; /* pointer to offset 12 */
	*p++ = (type >> 8) & 0xff;
	*p++ = type & 0xff;
	*p++ = 0x00; *p++ = 0x01; /* IN */
	*p++ = 0x00; *p++ = 0x00; *p++ = 0x01; *p++ = 0x2c; /* TTL=300 */
	*p++ = (rdlen >> 8) & 0xff;
	*p++ = rdlen & 0xff;
	memcpy(p, rdata, rdlen);
	p += rdlen;

	P->end = p - P->data;

	return P;
}

/*
 * Test CAA record parsing
 * RFC 8659: flags (1) + tag-length (1) + tag + value
 */
static void test_caa(void) {
	TEST_START("CAA basic");

	/* CAA 0 issue "pki.goog" */
	unsigned char rdata[] = {
		0x00,                   /* flags = 0 */
		0x05,                   /* tag length = 5 */
		'i', 's', 's', 'u', 'e', /* tag = "issue" */
		'p', 'k', 'i', '.', 'g', 'o', 'o', 'g' /* value = "pki.goog" */
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_CAA, "example.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (any.caa.flags != 0) {
		TEST_FAIL("flags: expected 0, got %d", any.caa.flags);
		free(P);
		return;
	}
	if (strcmp(any.caa.tag, "issue") != 0) {
		TEST_FAIL("tag: expected 'issue', got '%s'", any.caa.tag);
		free(P);
		return;
	}
	if (strcmp(any.caa.value, "pki.goog") != 0) {
		TEST_FAIL("value: expected 'pki.goog', got '%s'", any.caa.value);
		free(P);
		return;
	}

	/* Test print */
	char buf[256];
	dns_caa_print(buf, sizeof(buf), &any.caa);
	if (strstr(buf, "issue") == NULL || strstr(buf, "pki.goog") == NULL) {
		TEST_FAIL("print: '%s'", buf);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

static void test_caa_critical(void) {
	TEST_START("CAA critical flag");

	/* CAA 128 issuewild ";" */
	unsigned char rdata[] = {
		0x80,                         /* flags = 128 (critical) */
		0x09,                         /* tag length = 9 */
		'i', 's', 's', 'u', 'e', 'w', 'i', 'l', 'd',
		';'                           /* value = ";" */
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_CAA, "example.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (any.caa.flags != 128) {
		TEST_FAIL("flags: expected 128, got %d", any.caa.flags);
		free(P);
		return;
	}
	if (strcmp(any.caa.tag, "issuewild") != 0) {
		TEST_FAIL("tag: expected 'issuewild', got '%s'", any.caa.tag);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

/*
 * Test URI record parsing
 * RFC 7553: priority (2) + weight (2) + target
 */
static void test_uri(void) {
	TEST_START("URI basic");

	/* URI 10 1 "ftp://ftp.example.com/public" */
	unsigned char rdata[] = {
		0x00, 0x0a,             /* priority = 10 */
		0x00, 0x01,             /* weight = 1 */
		'f', 't', 'p', ':', '/', '/', 'f', 't', 'p', '.',
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		'/', 'p', 'u', 'b', 'l', 'i', 'c'
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_URI, "_ftp._tcp.example.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (any.uri.priority != 10) {
		TEST_FAIL("priority: expected 10, got %d", any.uri.priority);
		free(P);
		return;
	}
	if (any.uri.weight != 1) {
		TEST_FAIL("weight: expected 1, got %d", any.uri.weight);
		free(P);
		return;
	}
	if (strcmp(any.uri.target, "ftp://ftp.example.com/public") != 0) {
		TEST_FAIL("target: expected 'ftp://ftp.example.com/public', got '%s'", any.uri.target);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

/*
 * Test TLSA record parsing
 * RFC 6698: usage (1) + selector (1) + matching-type (1) + certificate-data
 */
static void test_tlsa(void) {
	TEST_START("TLSA basic");

	/* TLSA 3 1 1 <sha256-hash> */
	unsigned char rdata[] = {
		0x03,                   /* usage = 3 (DANE-EE) */
		0x01,                   /* selector = 1 (SubjectPublicKeyInfo) */
		0x01,                   /* matching type = 1 (SHA-256) */
		/* 32-byte SHA-256 hash */
		0x38, 0xa8, 0x81, 0x26, 0xa1, 0x5a, 0xe8, 0xe6,
		0x43, 0xce, 0x94, 0x47, 0xc3, 0xce, 0x9a, 0x87,
		0x4e, 0xa0, 0xe0, 0x52, 0x55, 0xd0, 0x7e, 0xe1,
		0x22, 0x27, 0x80, 0x9e, 0xdb, 0xe5, 0xc7, 0xf1
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_TLSA, "_25._tcp.mail.example.org");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (any.tlsa.usage != 3) {
		TEST_FAIL("usage: expected 3, got %d", any.tlsa.usage);
		free(P);
		return;
	}
	if (any.tlsa.selector != 1) {
		TEST_FAIL("selector: expected 1, got %d", any.tlsa.selector);
		free(P);
		return;
	}
	if (any.tlsa.matchtype != 1) {
		TEST_FAIL("matchtype: expected 1, got %d", any.tlsa.matchtype);
		free(P);
		return;
	}
	if (any.tlsa.datalen != 32) {
		TEST_FAIL("datalen: expected 32, got %zu", any.tlsa.datalen);
		free(P);
		return;
	}
	if (memcmp(any.tlsa.data, rdata + 3, 32) != 0) {
		TEST_FAIL("data mismatch");
		free(P);
		return;
	}

	/* Test print output */
	char buf[256];
	dns_tlsa_print(buf, sizeof(buf), &any.tlsa);
	if (strstr(buf, "3 1 1") == NULL) {
		TEST_FAIL("print missing '3 1 1': '%s'", buf);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

/*
 * Test SVCB/HTTPS record parsing
 * RFC 9460: priority (2) + target (wire format) + SvcParams
 */
static void test_svcb(void) {
	TEST_START("SVCB basic");

	/* SVCB 1 . alpn=h2 */
	unsigned char rdata[] = {
		0x00, 0x01,             /* priority = 1 */
		0x00,                   /* target = "." (root) */
		0x00, 0x01,             /* key = alpn (1) */
		0x00, 0x03,             /* length = 3 */
		0x02, 'h', '2'          /* alpn-id = "h2" */
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_SVCB, "_https._tcp.example.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (any.svcb.priority != 1) {
		TEST_FAIL("priority: expected 1, got %d", any.svcb.priority);
		free(P);
		return;
	}
	/* Target "." becomes empty string after expansion */
	if (any.svcb.target[0] != '\0' && strcmp(any.svcb.target, ".") != 0) {
		TEST_FAIL("target: expected '' or '.', got '%s'", any.svcb.target);
		free(P);
		return;
	}
	if (any.svcb.paramslen != 7) {
		TEST_FAIL("paramslen: expected 7, got %zu", any.svcb.paramslen);
		free(P);
		return;
	}

	/* Test print */
	char buf[256];
	dns_svcb_print(buf, sizeof(buf), &any.svcb);
	if (strstr(buf, "alpn=") == NULL || strstr(buf, "h2") == NULL) {
		TEST_FAIL("print missing alpn: '%s'", buf);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

static void test_https(void) {
	TEST_START("HTTPS with ipv4hint");

	/* HTTPS 1 . alpn=h3,h2 ipv4hint=104.16.123.96,104.16.124.96 */
	unsigned char rdata[] = {
		0x00, 0x01,             /* priority = 1 */
		0x00,                   /* target = "." */
		0x00, 0x01, 0x00, 0x06, /* key=alpn, len=6 */
		0x02, 'h', '3', 0x02, 'h', '2',
		0x00, 0x04, 0x00, 0x08, /* key=ipv4hint, len=8 */
		0x68, 0x10, 0x7b, 0x60, /* 104.16.123.96 */
		0x68, 0x10, 0x7c, 0x60  /* 104.16.124.96 */
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_HTTPS, "www.cloudflare.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (any.https.priority != 1) {
		TEST_FAIL("priority: expected 1, got %d", any.https.priority);
		free(P);
		return;
	}

	/* Test print */
	char buf[512];
	dns_svcb_print(buf, sizeof(buf), &any.https);
	if (strstr(buf, "104.16.123.96") == NULL) {
		TEST_FAIL("print missing ipv4hint: '%s'", buf);
		free(P);
		return;
	}
	if (strstr(buf, "h3") == NULL) {
		TEST_FAIL("print missing h3: '%s'", buf);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

static void test_https_ipv6(void) {
	TEST_START("HTTPS with ipv6hint");

	/* HTTPS 1 . ipv6hint=2606:4700::6810:7b60 */
	unsigned char rdata[] = {
		0x00, 0x01,             /* priority = 1 */
		0x00,                   /* target = "." */
		0x00, 0x06, 0x00, 0x10, /* key=ipv6hint, len=16 */
		0x26, 0x06, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x68, 0x10, 0x7b, 0x60
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_HTTPS, "example.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	/* Test print */
	char buf[512];
	dns_svcb_print(buf, sizeof(buf), &any.https);
	if (strstr(buf, "2606:4700") == NULL) {
		TEST_FAIL("print missing ipv6: '%s'", buf);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

static void test_svcb_aliasmode(void) {
	TEST_START("SVCB AliasMode (priority=0)");

	/* SVCB 0 pool.svc.example. (AliasMode) */
	unsigned char rdata[] = {
		0x00, 0x00,             /* priority = 0 (AliasMode) */
		0x04, 'p', 'o', 'o', 'l',
		0x03, 's', 'v', 'c',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x00
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_SVCB, "example.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (any.svcb.priority != 0) {
		TEST_FAIL("priority: expected 0, got %d", any.svcb.priority);
		free(P);
		return;
	}
	if (strstr(any.svcb.target, "pool.svc.example") == NULL) {
		TEST_FAIL("target: expected 'pool.svc.example', got '%s'", any.svcb.target);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

/*
 * Test DNSKEY record parsing
 * RFC 4034: flags (2) + protocol (1) + algorithm (1) + public-key
 */
static void test_dnskey(void) {
	TEST_START("DNSKEY KSK");

	/* DNSKEY 257 3 13 <base64-key> - 257 = KSK */
	unsigned char rdata[] = {
		0x01, 0x01,             /* flags = 257 (KSK) */
		0x03,                   /* protocol = 3 */
		0x0d,                   /* algorithm = 13 (ECDSAP256SHA256) */
		/* 64-byte ECDSA P-256 public key */
		0x99, 0xdb, 0x30, 0xc1, 0x4b, 0xab, 0xdc, 0x33,
		0xd6, 0xdf, 0x66, 0x3a, 0x2e, 0x15, 0xf7, 0x12,
		0x58, 0x4f, 0x09, 0x8e, 0x8d, 0x4e, 0x8d, 0x1d,
		0xc4, 0x28, 0xe3, 0x9a, 0x8a, 0x49, 0x97, 0xe1,
		0xaa, 0x27, 0x1a, 0x55, 0x5d, 0xc9, 0x07, 0x01,
		0xe1, 0x7e, 0x2a, 0x4c, 0x4b, 0x6f, 0x12, 0x0b,
		0x7c, 0x35, 0xd4, 0x4f, 0x4a, 0xc0, 0x2b, 0xd8,
		0x94, 0xef, 0x32, 0xeb, 0x9d, 0xb6, 0x5e, 0x19
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_DNSKEY, "cloudflare.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (any.dnskey.flags != 257) {
		TEST_FAIL("flags: expected 257, got %d", any.dnskey.flags);
		free(P);
		return;
	}
	if (any.dnskey.protocol != 3) {
		TEST_FAIL("protocol: expected 3, got %d", any.dnskey.protocol);
		free(P);
		return;
	}
	if (any.dnskey.algorithm != 13) {
		TEST_FAIL("algorithm: expected 13, got %d", any.dnskey.algorithm);
		free(P);
		return;
	}
	if (any.dnskey.pubkeylen != 64) {
		TEST_FAIL("pubkeylen: expected 64, got %zu", any.dnskey.pubkeylen);
		free(P);
		return;
	}

	/* Test print - should contain base64 key */
	char buf[512];
	dns_dnskey_print(buf, sizeof(buf), &any.dnskey);
	if (strstr(buf, "257 3 13") == NULL) {
		TEST_FAIL("print missing '257 3 13': '%s'", buf);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

static void test_dnskey_zsk(void) {
	TEST_START("DNSKEY ZSK");

	/* DNSKEY 256 3 13 <key> - 256 = ZSK */
	unsigned char rdata[] = {
		0x01, 0x00,             /* flags = 256 (ZSK) */
		0x03,                   /* protocol = 3 */
		0x0d,                   /* algorithm = 13 */
		/* 64-byte key */
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_DNSKEY, "example.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (any.dnskey.flags != 256) {
		TEST_FAIL("flags: expected 256, got %d", any.dnskey.flags);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

/*
 * Test DS record parsing
 * RFC 4034: keytag (2) + algorithm (1) + digest-type (1) + digest
 */
static void test_ds(void) {
	TEST_START("DS SHA-256");

	/* DS 2371 13 2 <sha256-digest> */
	unsigned char rdata[] = {
		0x09, 0x43,             /* keytag = 2371 */
		0x0d,                   /* algorithm = 13 (ECDSAP256SHA256) */
		0x02,                   /* digest type = 2 (SHA-256) */
		/* 32-byte SHA-256 digest */
		0x32, 0x99, 0x68, 0x39, 0xa6, 0xd8, 0x08, 0xaf,
		0xe3, 0xeb, 0x4a, 0x79, 0x5a, 0x0e, 0x6a, 0x7a,
		0x39, 0xa7, 0x6f, 0xc5, 0x2f, 0xf2, 0x28, 0xb2,
		0x2b, 0x76, 0xf6, 0xd6, 0x38, 0x26, 0xf2, 0xb9
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_DS, "cloudflare.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (any.ds.keytag != 2371) {
		TEST_FAIL("keytag: expected 2371, got %d", any.ds.keytag);
		free(P);
		return;
	}
	if (any.ds.algorithm != 13) {
		TEST_FAIL("algorithm: expected 13, got %d", any.ds.algorithm);
		free(P);
		return;
	}
	if (any.ds.digtype != 2) {
		TEST_FAIL("digtype: expected 2, got %d", any.ds.digtype);
		free(P);
		return;
	}
	if (any.ds.digestlen != 32) {
		TEST_FAIL("digestlen: expected 32, got %zu", any.ds.digestlen);
		free(P);
		return;
	}

	/* Test print */
	char buf[256];
	dns_ds_print(buf, sizeof(buf), &any.ds);
	if (strstr(buf, "2371 13 2") == NULL) {
		TEST_FAIL("print missing '2371 13 2': '%s'", buf);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

/*
 * Test RRSIG record parsing
 * RFC 4034: type-covered (2) + algorithm (1) + labels (1) + original-ttl (4)
 *           + expiration (4) + inception (4) + keytag (2) + signer + signature
 */
static void test_rrsig(void) {
	TEST_START("RRSIG basic");

	/* RRSIG A 13 2 300 20251231235959 20251201000000 12345 example.com. <sig> */
	unsigned char rdata[] = {
		0x00, 0x01,             /* type covered = A (1) */
		0x0d,                   /* algorithm = 13 */
		0x02,                   /* labels = 2 */
		0x00, 0x00, 0x01, 0x2c, /* original TTL = 300 */
		0x67, 0x74, 0x42, 0xef, /* expiration = 20251231235959 (approx timestamp) */
		0x67, 0x4b, 0xfe, 0x80, /* inception = 20251201000000 (approx timestamp) */
		0x30, 0x39,             /* keytag = 12345 */
		/* signer name: example.com */
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		/* signature (64 bytes for ECDSA P-256) */
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_RRSIG, "example.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (any.rrsig.covered != DNS_T_A) {
		TEST_FAIL("covered: expected %d, got %d", DNS_T_A, any.rrsig.covered);
		free(P);
		return;
	}
	if (any.rrsig.algorithm != 13) {
		TEST_FAIL("algorithm: expected 13, got %d", any.rrsig.algorithm);
		free(P);
		return;
	}
	if (any.rrsig.labels != 2) {
		TEST_FAIL("labels: expected 2, got %d", any.rrsig.labels);
		free(P);
		return;
	}
	if (any.rrsig.origttl != 300) {
		TEST_FAIL("origttl: expected 300, got %u", any.rrsig.origttl);
		free(P);
		return;
	}
	if (any.rrsig.keytag != 12345) {
		TEST_FAIL("keytag: expected 12345, got %d", any.rrsig.keytag);
		free(P);
		return;
	}
	if (strstr(any.rrsig.signer, "example.com") == NULL) {
		TEST_FAIL("signer: expected 'example.com', got '%s'", any.rrsig.signer);
		free(P);
		return;
	}
	if (any.rrsig.siglen != 64) {
		TEST_FAIL("siglen: expected 64, got %zu", any.rrsig.siglen);
		free(P);
		return;
	}

	/* Test print */
	char buf[512];
	dns_rrsig_print(buf, sizeof(buf), &any.rrsig);
	if (strstr(buf, "A 13 2 300") == NULL) {
		TEST_FAIL("print missing 'A 13 2 300': '%s'", buf);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

/*
 * Test NSEC record parsing
 * RFC 4034: next-domain-name + type-bit-maps
 */
static void test_nsec(void) {
	TEST_START("NSEC basic");

	/* NSEC beta.example.com. A NS SOA MX RRSIG NSEC */
	unsigned char rdata[] = {
		/* next domain: beta.example.com */
		0x04, 'b', 'e', 't', 'a',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		/* type bitmap: window 0, length 7 */
		0x00,                   /* window block 0 */
		0x07,                   /* bitmap length = 7 */
		/* bits: A(1), NS(2), SOA(6), MX(15), RRSIG(46), NSEC(47) */
		/* byte 0: types 0-7:   00000110 = 0x06 (bits 1,2 = A,NS) - but bit 0 is type 0 */
		/* Actually: bit 0 = type 0, bit 1 = type 1 (A), bit 2 = type 2 (NS) */
		/* So for A(1), NS(2): byte 0 bits 1,2 set = 0x60 (big-endian bit order) */
		0x62,                   /* A(1), NS(2), SOA(6): bits 1,2,6 in BE order */
		0x00,                   /* types 8-15: MX is type 15 */
		0x01,                   /* MX (15) - bit 7 of this byte */
		0x00, 0x00, 0x00,       /* types 16-39 */
		0x03                    /* types 40-47: RRSIG(46), NSEC(47) - bits 6,7 */
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_NSEC, "alpha.example.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (strstr(any.nsec.next, "beta.example.com") == NULL) {
		TEST_FAIL("next: expected 'beta.example.com', got '%s'", any.nsec.next);
		free(P);
		return;
	}
	if (any.nsec.typemaplen != 9) {
		TEST_FAIL("typemaplen: expected 9, got %zu", any.nsec.typemaplen);
		free(P);
		return;
	}

	/* Test print */
	char buf[512];
	dns_nsec_print(buf, sizeof(buf), &any.nsec);
	if (strstr(buf, "beta.example.com") == NULL) {
		TEST_FAIL("print missing next domain: '%s'", buf);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

/*
 * Test NSEC3 record parsing
 * RFC 5155: algorithm + flags + iterations + salt-len + salt + hash-len + hash + type-bitmaps
 */
static void test_nsec3(void) {
	TEST_START("NSEC3 basic");

	/* NSEC3 1 0 10 aabbccdd <base32-hash> A NS SOA */
	unsigned char rdata[] = {
		0x01,                   /* hash algorithm = 1 (SHA-1) */
		0x00,                   /* flags = 0 */
		0x00, 0x0a,             /* iterations = 10 */
		0x04,                   /* salt length = 4 */
		0xaa, 0xbb, 0xcc, 0xdd, /* salt */
		0x14,                   /* hash length = 20 (SHA-1) */
		/* 20-byte SHA-1 hash */
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14,
		/* type bitmap: window 0, length 1 */
		0x00,                   /* window 0 */
		0x01,                   /* bitmap length = 1 */
		0x62                    /* A(1), NS(2), SOA(6) */
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_NSEC3, "example.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (any.nsec3.algorithm != 1) {
		TEST_FAIL("algorithm: expected 1, got %d", any.nsec3.algorithm);
		free(P);
		return;
	}
	if (any.nsec3.flags != 0) {
		TEST_FAIL("flags: expected 0, got %d", any.nsec3.flags);
		free(P);
		return;
	}
	if (any.nsec3.iterations != 10) {
		TEST_FAIL("iterations: expected 10, got %d", any.nsec3.iterations);
		free(P);
		return;
	}
	if (any.nsec3.saltlen != 4) {
		TEST_FAIL("saltlen: expected 4, got %zu", any.nsec3.saltlen);
		free(P);
		return;
	}
	if (any.nsec3.nexthashlen != 20) {
		TEST_FAIL("nexthashlen: expected 20, got %zu", any.nsec3.nexthashlen);
		free(P);
		return;
	}

	/* Test print */
	char buf[512];
	dns_nsec3_print(buf, sizeof(buf), &any.nsec3);
	if (strstr(buf, "1 0 10") == NULL) {
		TEST_FAIL("print missing '1 0 10': '%s'", buf);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

static void test_nsec3_nosalt(void) {
	TEST_START("NSEC3 no salt");

	/* NSEC3 1 1 0 - <hash> A */
	unsigned char rdata[] = {
		0x01,                   /* algorithm = 1 */
		0x01,                   /* flags = 1 (opt-out) */
		0x00, 0x00,             /* iterations = 0 */
		0x00,                   /* salt length = 0 (no salt) */
		0x14,                   /* hash length = 20 */
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14,
		/* type bitmap */
		0x00, 0x01, 0x40        /* A(1) */
	};

	struct dns_packet *P = make_packet(rdata, sizeof(rdata), DNS_T_NSEC3, "example.com");
	if (!P) { TEST_FAIL("make_packet"); return; }

	struct dns_rr rr;
	struct dns_rr_i *I = dns_rr_i_new(P, .section = DNS_S_AN);
	int error;

	if (!dns_rr_grep(&rr, 1, I, P, &error)) {
		TEST_FAIL("dns_rr_grep: %s", dns_strerror(error));
		free(P);
		return;
	}

	union dns_any any;
	dns_any_init(&any, sizeof(any));
	error = dns_any_parse(&any, &rr, P);
	if (error) {
		TEST_FAIL("dns_any_parse: %s", dns_strerror(error));
		free(P);
		return;
	}

	if (any.nsec3.saltlen != 0) {
		TEST_FAIL("saltlen: expected 0, got %zu", any.nsec3.saltlen);
		free(P);
		return;
	}
	if (any.nsec3.flags != 1) {
		TEST_FAIL("flags: expected 1, got %d", any.nsec3.flags);
		free(P);
		return;
	}

	free(P);
	TEST_OK();
}

int main(void) {
	fprintf(stderr, "Testing RR type parsing:\n");

	/* CAA tests */
	fprintf(stderr, "\nCAA:\n");
	test_caa();
	test_caa_critical();

	/* URI tests */
	fprintf(stderr, "\nURI:\n");
	test_uri();

	/* TLSA tests */
	fprintf(stderr, "\nTLSA:\n");
	test_tlsa();

	/* SVCB/HTTPS tests */
	fprintf(stderr, "\nSVCB/HTTPS:\n");
	test_svcb();
	test_https();
	test_https_ipv6();
	test_svcb_aliasmode();

	/* DNSKEY tests */
	fprintf(stderr, "\nDNSKEY:\n");
	test_dnskey();
	test_dnskey_zsk();

	/* DS tests */
	fprintf(stderr, "\nDS:\n");
	test_ds();

	/* RRSIG tests */
	fprintf(stderr, "\nRRSIG:\n");
	test_rrsig();

	/* NSEC tests */
	fprintf(stderr, "\nNSEC:\n");
	test_nsec();

	/* NSEC3 tests */
	fprintf(stderr, "\nNSEC3:\n");
	test_nsec3();
	test_nsec3_nosalt();

	fprintf(stderr, "\n--------------------\n");
	fprintf(stderr, "Tests: %d, Failures: %d\n", test_count, fail_count);

	if (fail_count > 0) {
		fprintf(stderr, "FAILED\n");
		return 1;
	}

	fprintf(stderr, "ALL TESTS PASSED\n");
	return 0;
}
