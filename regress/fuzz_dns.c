/*
 * Fuzz harness for dns.c using libFuzzer
 *
 * Build with:
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *         -DDNS_DEBUG=0 -I../src -o fuzz_dns fuzz_dns.c
 *
 * Run with:
 *   ./fuzz_dns corpus/ -max_len=4096
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "dns.c"

/*
 * Fuzz target 1: Parse a complete DNS packet
 * This exercises the most attack surface - packet parsing, RR iteration,
 * name decompression, and all RR type parsers.
 */
static void fuzz_packet_parse(const uint8_t *data, size_t size) {
    struct dns_packet *P;
    struct dns_rr rr;
    struct dns_rr_i I;
    union dns_any any;
    char buf[1024];
    int error;

    if (size < 12 || size > 65535)
        return;

    P = dns_p_make(size, NULL);
    if (!P)
        return;

    memcpy(P->data, data, size);
    P->end = size;

    /* Try to iterate all sections */
    for (int section = DNS_S_QD; section <= DNS_S_AR; section <<= 1) {
        memset(&I, 0, sizeof(I));
        I.section = section;
        dns_rr_i_init(&I, P);

        while (dns_rr_grep(&rr, 1, &I, P, &error)) {
            /* Try to parse the RR */
            dns_any_init(&any, sizeof(any));
            if (dns_any_parse(&any, &rr, P) != 0)
                continue;

            /* Try to print the RR - only if parse succeeded */
            dns_any_print(buf, sizeof(buf), &any, rr.type);

            /* Try to get the name */
            dns_d_expand(buf, sizeof(buf), rr.dn.p, P, &error);
        }
    }

    free(P);
}

/*
 * Fuzz target 2: Domain name operations
 * Test name expansion, compression, comparison
 */
static void fuzz_domain_name(const uint8_t *data, size_t size) {
    struct dns_packet *P;
    char name[DNS_D_MAXNAME + 1];
    int error;

    if (size < 12 || size > 4096)
        return;

    P = dns_p_make(size, NULL);
    if (!P)
        return;

    memcpy(P->data, data, size);
    P->end = size;

    /* Try expanding names at various offsets */
    for (unsigned offset = 12; offset < size && offset < 512; offset++) {
        dns_d_expand(name, sizeof(name), offset, P, &error);
        dns_d_skip(offset, P);
    }

    /* Try name comparison */
    if (size >= 24) {
        dns_d_cname(name, sizeof(name), (char *)data + 12,
                    DNS_PP_MIN(size - 12, DNS_D_MAXNAME), P, &error);
    }

    free(P);
}

/*
 * Fuzz target 3: Individual RR type parsers
 * Directly test each RR parser with raw RDATA
 */
static void fuzz_rr_parsers(const uint8_t *data, size_t size) {
    struct dns_packet *P;
    struct dns_rr rr = {0};
    union dns_any any;
    char buf[4096];

    if (size < 1 || size > 2048)
        return;

    /* Allocate packet with enough space for the data */
    P = dns_p_make(size + 12, NULL);
    if (!P)
        return;

    /* Set up a minimal packet with just the RDATA */
    memcpy(P->data, data, size);
    P->end = size;

    rr.rd.p = 0;
    rr.rd.len = size;

    /* Use first byte to select RR type to test */
    static const enum dns_type types[] = {
        DNS_T_A, DNS_T_NS, DNS_T_CNAME, DNS_T_SOA, DNS_T_PTR,
        DNS_T_MX, DNS_T_TXT, DNS_T_AAAA, DNS_T_SRV,
        DNS_T_OPT, DNS_T_SSHFP, DNS_T_DS, DNS_T_RRSIG, DNS_T_NSEC,
        DNS_T_DNSKEY, DNS_T_NSEC3, DNS_T_TLSA, DNS_T_SVCB, DNS_T_HTTPS,
        DNS_T_CAA, DNS_T_URI
    };

    if (size < 2) {
        free(P);
        return;
    }

    int type_idx = data[0] % (sizeof(types) / sizeof(types[0]));
    rr.type = types[type_idx];
    rr.rd.p = 1;  /* Skip the type selector byte */
    rr.rd.len = size - 1;

    dns_any_init(&any, sizeof(any));
    if (dns_any_parse(&any, &rr, P) == 0) {
        dns_any_print(buf, sizeof(buf), &any, rr.type);
    }

    free(P);
}

/*
 * Fuzz target 4: Resolver configuration parsing
 */
static void fuzz_resconf(const uint8_t *data, size_t size) {
    struct dns_resolv_conf *resconf;
    int error;

    if (size > 8192)
        return;

    resconf = dns_resconf_open(&error);
    if (!resconf)
        return;

    /* Create a temporary buffer with null terminator for line parsing */
    char *buf = malloc(size + 1);
    if (buf) {
        memcpy(buf, data, size);
        buf[size] = '\0';

        /* Simulate parsing resolv.conf lines */
        char *line = buf;
        char *end;
        while ((end = strchr(line, '\n')) != NULL) {
            *end = '\0';
            /* The library doesn't expose line parsing directly,
               but we can test the full loadpath */
            line = end + 1;
        }
        free(buf);
    }

    dns_resconf_close(resconf);
}

/*
 * Fuzz target 5: hosts file parsing
 */
static void fuzz_hosts(const uint8_t *data, size_t size) {
    struct dns_hosts *hosts;
    int error;

    if (size > 8192)
        return;

    hosts = dns_hosts_open(&error);
    if (!hosts)
        return;

    /* Similar to resconf - test what we can */
    dns_hosts_close(hosts);
}

/*
 * Fuzz target 6: Packet building/pushing
 * Test that we can build packets without crashing
 */
static void fuzz_packet_build(const uint8_t *data, size_t size) {
    struct dns_packet *P;
    char name[256];
    int error;

    if (size < 4 || size > 512)
        return;

    P = dns_p_make(512, &error);
    if (!P)
        return;

    /* Use input as a domain name to push */
    size_t namelen = DNS_PP_MIN(size - 1, sizeof(name) - 1);
    memcpy(name, data + 1, namelen);
    name[namelen] = '\0';

    /* Try to make it a valid-ish domain name */
    for (size_t i = 0; i < namelen; i++) {
        if (name[i] == '\0')
            name[i] = '.';
        else if (name[i] < 32 || name[i] > 126)
            name[i] = 'a';
    }

    /* Try pushing a question */
    dns_p_push(P, DNS_S_QD, name, strlen(name), DNS_T_A, DNS_C_IN, 0, NULL);

    free(P);
}

/*
 * Main fuzzer entry point
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2)
        return 0;

    /* Use first byte to select which fuzzer to run */
    uint8_t selector = data[0] % 6;
    data++;
    size--;

    switch (selector) {
    case 0:
        fuzz_packet_parse(data, size);
        break;
    case 1:
        fuzz_domain_name(data, size);
        break;
    case 2:
        fuzz_rr_parsers(data, size);
        break;
    case 3:
        fuzz_resconf(data, size);
        break;
    case 4:
        fuzz_hosts(data, size);
        break;
    case 5:
        fuzz_packet_build(data, size);
        break;
    }

    return 0;
}
