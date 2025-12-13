#!/bin/sh
#
# Validate RR parsing by comparing ./dns output to dig output
# This fetches real DNS records and compares the parsed output
#

DNS_CMD="../src/dns"
PASS=0
FAIL=0

normalize() {
    # Remove all whitespace, uppercase hex
    tr -d ' \t\n' | tr 'a-f' 'A-F'
}

compare_output() {
    query="$1"
    type="$2"

    printf "%-8s %-40s " "$type" "$query"

    # Get dig output (+short gives just RDATA)
    dig_raw=$(dig @8.8.8.8 "$query" "$type" +short 2>/dev/null | head -1)
    dig_out=$(echo "$dig_raw" | normalize)

    # Get ./dns output - match lines starting with the query name
    # Format: "name. TTL IN TYPE RDATA..."
    dns_raw=$($DNS_CMD send-query 8.8.8.8 -q "$query" -t "$type" 2>&1 | \
        grep -E "^[a-zA-Z0-9._-]+\. [0-9]+ IN $type " | head -1 | \
        awk '{for(i=5;i<=NF;i++) printf "%s", (i>5?" ":"") $i; print ""}')
    dns_out=$(echo "$dns_raw" | normalize)

    if [ -z "$dig_out" ]; then
        echo "SKIP (no response)"
        return 0
    fi

    if [ -z "$dns_out" ]; then
        echo "FAIL (./dns no response)"
        FAIL=$((FAIL + 1))
        return 1
    fi

    # Compare normalized output
    if [ "$dig_out" = "$dns_out" ]; then
        echo "PASS"
        PASS=$((PASS + 1))
        return 0
    else
        echo "MISMATCH"
        echo "    dig: $dig_raw"
        echo "    dns: $dns_raw"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

# Compare multi-record RRsets (order-independent)
compare_multi() {
    query="$1"
    type="$2"

    printf "%-8s %-40s " "$type" "$query"

    # Get all dig records, sort them
    dig_all=$(dig @8.8.8.8 "$query" "$type" +short 2>/dev/null | sort)
    if [ -z "$dig_all" ]; then
        echo "SKIP (no response)"
        return 0
    fi

    # Get all ./dns records, extract RDATA, sort
    dns_all=$($DNS_CMD send-query 8.8.8.8 -q "$query" -t "$type" 2>&1 | \
        grep -E "^[a-zA-Z0-9._-]+\. [0-9]+ IN $type " | \
        awk '{for(i=5;i<=NF;i++) printf "%s", (i>5?" ":"") $i; print ""}' | sort)

    if [ -z "$dns_all" ]; then
        echo "FAIL (./dns no response)"
        FAIL=$((FAIL + 1))
        return 1
    fi

    # Compare sorted, normalized outputs
    dig_norm=$(echo "$dig_all" | normalize)
    dns_norm=$(echo "$dns_all" | normalize)

    if [ "$dig_norm" = "$dns_norm" ]; then
        echo "PASS"
        PASS=$((PASS + 1))
        return 0
    else
        echo "MISMATCH"
        echo "    dig records: $(echo "$dig_all" | wc -l)"
        echo "    dns records: $(echo "$dns_all" | wc -l)"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

echo "=============================================="
echo "Validating RR parsing: ./dns vs dig"
echo "=============================================="
echo ""

# CAA
compare_output "google.com" "CAA"
compare_output "letsencrypt.org" "CAA"

# HTTPS/SVCB
compare_output "www.cloudflare.com" "HTTPS"
compare_output "crypto.cloudflare.com" "HTTPS"

# DNSKEY (may have multiple records - use order-independent compare)
compare_multi "cloudflare.com" "DNSKEY"

# DS (Delegation Signer)
compare_output "cloudflare.com" "DS"

# TLSA (DANE)
compare_output "_25._tcp.mail.ietf.org" "TLSA"

echo ""
echo "=============================================="
printf "Results: %d passed, %d failed\n" "$PASS" "$FAIL"
echo "=============================================="

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
