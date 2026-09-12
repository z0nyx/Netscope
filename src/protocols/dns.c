#include "netscope/protocols/dns.h"

#include <stdio.h>
#include <string.h>

#include "netscope/util.h"

/*
 * A DNS name is a sequence of length-prefixed labels ended by a zero byte,
 * except a label may instead be a 2-byte pointer (top two bits set) to
 * another offset in the message, letting names share a common suffix. A
 * hostile packet can chain pointers into a cycle (including a label
 * pointing at itself), which would otherwise make this loop forever;
 * NS_DNS_MAX_JUMPS bounds the work independently of packet size or cycle
 * length. *end_offset is the offset right after the name as written at
 * `offset` (past the terminator, or past a leading pointer) -- not
 * affected by where a pointer jumps to -- which is what callers need to
 * continue parsing sibling fields.
 */
static ns_parse_status_t ns_dns_decode_name(const uint8_t *data, size_t length, size_t offset,
                                            char *out, size_t out_len, size_t *end_offset) {
    size_t pos = offset;
    size_t out_pos = 0;
    bool end_set = false;
    int jumps = 0;

    if (out_len == 0) {
        return NS_PARSE_MALFORMED;
    }

    for (;;) {
        uint8_t len_byte;
        if (!ns_read_u8(data, length, pos, &len_byte)) {
            return NS_PARSE_TRUNCATED;
        }

        if ((len_byte & 0xC0u) == 0xC0u) {
            uint16_t ptr_field;
            if (!ns_read_u16_be(data, length, pos, &ptr_field)) {
                return NS_PARSE_TRUNCATED;
            }
            if (!end_set) {
                *end_offset = pos + 2;
                end_set = true;
            }
            jumps++;
            if (jumps > NS_DNS_MAX_JUMPS) {
                return NS_PARSE_MALFORMED;
            }
            pos = (size_t) (ptr_field & 0x3FFFu);
            continue;
        }

        /* Top bits 01/10 are reserved by RFC 1035; a plain label's length
         * (bottom 6 bits) can therefore never legally exceed 63. */
        if ((len_byte & 0xC0u) != 0) {
            return NS_PARSE_MALFORMED;
        }

        if (len_byte == 0) {
            if (!end_set) {
                *end_offset = pos + 1;
            }
            break;
        }

        uint8_t label_len = len_byte;
        pos += 1;
        if (!ns_bounds_check(length, pos, label_len)) {
            return NS_PARSE_TRUNCATED;
        }
        size_t needed = out_pos + label_len + 1;
        if (needed >= out_len) {
            return NS_PARSE_MALFORMED;
        }
        if (out_pos != 0) {
            out[out_pos++] = '.';
        }
        memcpy(out + out_pos, data + pos, label_len);
        out_pos += label_len;
        pos += label_len;
    }

    if (out_pos == 0) {
        out[out_pos++] = '.';
    }
    out[out_pos] = '\0';
    return NS_PARSE_OK;
}

static ns_parse_status_t ns_dns_parse_question(const uint8_t *data, size_t length, size_t *offset,
                                               ns_dns_question_t *out) {
    char scratch[NS_DNS_MAX_NAME + 1];
    char *name_buf = (out != NULL) ? out->name : scratch;
    size_t name_buf_len = (out != NULL) ? sizeof(out->name) : sizeof(scratch);

    size_t name_end;
    ns_parse_status_t status =
        ns_dns_decode_name(data, length, *offset, name_buf, name_buf_len, &name_end);
    if (status != NS_PARSE_OK) {
        return status;
    }

    /* Checked once, against name_end directly, before any "name_end + k"
     * addition is formed: length - name_end cannot underflow (the check
     * above), and every offset used below is <= name_end + 4, so none of
     * them can overflow size_t either. See ns_bounds_check(). */
    if (!ns_bounds_check(length, name_end, 4)) {
        return NS_PARSE_TRUNCATED;
    }

    uint16_t type, qclass;
    ns_read_u16_be(data, length, name_end, &type);
    ns_read_u16_be(data, length, name_end + 2, &qclass);

    if (out != NULL) {
        out->type = type;
        out->qclass = qclass;
    }
    *offset = name_end + 4;
    return NS_PARSE_OK;
}

static bool ns_dns_format_a(const uint8_t *data, size_t length, size_t rdata_offset,
                            uint16_t rdlength, char *out, size_t out_len) {
    if (rdlength != 4 || !ns_bounds_check(length, rdata_offset, 4)) {
        return false;
    }
    uint32_t addr;
    memcpy(&addr, data + rdata_offset, 4);
    ns_format_ipv4(addr, out, out_len);
    return true;
}

static bool ns_dns_format_aaaa(const uint8_t *data, size_t length, size_t rdata_offset,
                               uint16_t rdlength, char *out, size_t out_len) {
    if (rdlength != 16 || !ns_bounds_check(length, rdata_offset, 16)) {
        return false;
    }
    ns_format_ipv6(data + rdata_offset, out, out_len);
    return true;
}

static bool ns_dns_format_name_rdata(const uint8_t *data, size_t length, size_t rdata_offset,
                                     char *out, size_t out_len) {
    size_t end;
    return ns_dns_decode_name(data, length, rdata_offset, out, out_len, &end) == NS_PARSE_OK;
}

static bool ns_dns_format_mx(const uint8_t *data, size_t length, size_t rdata_offset, char *out,
                             size_t out_len) {
    uint16_t preference;
    if (!ns_bounds_check(length, rdata_offset, 2) ||
        !ns_read_u16_be(data, length, rdata_offset, &preference)) {
        return false;
    }
    char name[NS_DNS_MAX_NAME + 1];
    size_t end;
    if (ns_dns_decode_name(data, length, rdata_offset + 2, name, sizeof(name), &end) !=
        NS_PARSE_OK) {
        return false;
    }
    snprintf(out, out_len, "%u %s", preference, name);
    return true;
}

static bool ns_dns_format_txt(const uint8_t *data, size_t length, size_t rdata_offset,
                              uint16_t rdlength, char *out, size_t out_len) {
    if (!ns_bounds_check(length, rdata_offset, rdlength)) {
        return false;
    }
    size_t pos = 0;
    size_t out_pos = 0;
    out[0] = '\0';
    while (pos < rdlength && out_pos + 1 < out_len) {
        uint8_t seg_len = data[rdata_offset + pos];
        pos += 1;
        if (pos + seg_len > rdlength) {
            break;
        }
        size_t copy = seg_len;
        if (out_pos + copy >= out_len) {
            copy = out_len - out_pos - 1;
        }
        memcpy(out + out_pos, data + rdata_offset + pos, copy);
        out_pos += copy;
        pos += seg_len;
    }
    out[out_pos] = '\0';
    return true;
}

static void ns_dns_format_rdata(const uint8_t *data, size_t length, size_t rdata_offset,
                                uint16_t rdlength, uint16_t type, char *out, size_t out_len) {
    bool ok;
    switch (type) {
        case NS_DNS_TYPE_A:
            ok = ns_dns_format_a(data, length, rdata_offset, rdlength, out, out_len);
            break;
        case NS_DNS_TYPE_AAAA:
            ok = ns_dns_format_aaaa(data, length, rdata_offset, rdlength, out, out_len);
            break;
        case NS_DNS_TYPE_CNAME:
        case NS_DNS_TYPE_NS:
        case NS_DNS_TYPE_PTR:
            ok = ns_dns_format_name_rdata(data, length, rdata_offset, out, out_len);
            break;
        case NS_DNS_TYPE_MX:
            ok = ns_dns_format_mx(data, length, rdata_offset, out, out_len);
            break;
        case NS_DNS_TYPE_TXT:
            ok = ns_dns_format_txt(data, length, rdata_offset, rdlength, out, out_len);
            break;
        default:
            ok = false;
            break;
    }
    if (ok) {
        return;
    }
    snprintf(out, out_len, "<%u bytes>", rdlength);
}

static ns_parse_status_t ns_dns_parse_record(const uint8_t *data, size_t length, size_t *offset,
                                             ns_dns_record_t *out) {
    char name[NS_DNS_MAX_NAME + 1];
    size_t name_end;
    ns_parse_status_t status =
        ns_dns_decode_name(data, length, *offset, name, sizeof(name), &name_end);
    if (status != NS_PARSE_OK) {
        return status;
    }

    /* type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes, validated
     * against name_end directly (see ns_dns_parse_question for why this
     * ordering matters) before any "name_end + k" offset is formed. */
    if (!ns_bounds_check(length, name_end, 10)) {
        return NS_PARSE_TRUNCATED;
    }

    uint16_t type, rclass, rdlength;
    uint32_t ttl;
    ns_read_u16_be(data, length, name_end, &type);
    ns_read_u16_be(data, length, name_end + 2, &rclass);
    ns_read_u32_be(data, length, name_end + 4, &ttl);
    ns_read_u16_be(data, length, name_end + 8, &rdlength);

    size_t rdata_offset = name_end + 10;
    if (!ns_bounds_check(length, rdata_offset, rdlength)) {
        return NS_PARSE_TRUNCATED;
    }

    if (out != NULL) {
        memcpy(out->name, name, sizeof(out->name));
        out->type = type;
        out->rclass = rclass;
        out->ttl = ttl;
        out->rdlength = rdlength;
        ns_dns_format_rdata(data, length, rdata_offset, rdlength, type, out->rdata_text,
                            sizeof(out->rdata_text));
    }

    *offset = rdata_offset + rdlength;
    return NS_PARSE_OK;
}

ns_parse_status_t ns_parse_dns(const uint8_t *data, size_t length, ns_dns_info_t *out) {
    if (!ns_bounds_check(length, 0, NS_DNS_HEADER_LEN)) {
        return NS_PARSE_TRUNCATED;
    }

    uint16_t txn_id, flags, qdcount, ancount, nscount, arcount;
    ns_read_u16_be(data, length, 0, &txn_id);
    ns_read_u16_be(data, length, 2, &flags);
    ns_read_u16_be(data, length, 4, &qdcount);
    ns_read_u16_be(data, length, 6, &ancount);
    ns_read_u16_be(data, length, 8, &nscount);
    ns_read_u16_be(data, length, 10, &arcount);

    memset(out, 0, sizeof(*out));
    out->transaction_id = txn_id;
    out->flags = flags;
    out->is_response = (flags & 0x8000u) != 0;
    out->question_count = qdcount;
    out->answer_count = ancount;
    out->authority_count = nscount;
    out->additional_count = arcount;

    size_t offset = NS_DNS_HEADER_LEN;

    for (uint16_t i = 0; i < qdcount; i++) {
        ns_dns_question_t *slot =
            (i < NS_DNS_MAX_QUESTIONS) ? &out->questions[out->decoded_question_count] : NULL;
        ns_parse_status_t status = ns_dns_parse_question(data, length, &offset, slot);
        if (status != NS_PARSE_OK) {
            return status;
        }
        if (slot != NULL) {
            out->decoded_question_count++;
        }
    }

    for (uint16_t i = 0; i < ancount && i < NS_DNS_MAX_ANSWERS; i++) {
        ns_dns_record_t *slot = &out->answers[out->decoded_answer_count];
        ns_parse_status_t status = ns_dns_parse_record(data, length, &offset, slot);
        if (status != NS_PARSE_OK) {
            return status;
        }
        out->decoded_answer_count++;
    }

    return NS_PARSE_OK;
}

const char *ns_dns_type_name(uint16_t type, char *buf, size_t buf_len) {
    switch (type) {
        case NS_DNS_TYPE_A:
            return "A";
        case NS_DNS_TYPE_NS:
            return "NS";
        case NS_DNS_TYPE_CNAME:
            return "CNAME";
        case NS_DNS_TYPE_PTR:
            return "PTR";
        case NS_DNS_TYPE_MX:
            return "MX";
        case NS_DNS_TYPE_TXT:
            return "TXT";
        case NS_DNS_TYPE_AAAA:
            return "AAAA";
        default:
            snprintf(buf, buf_len, "TYPE%u", type);
            return buf;
    }
}
