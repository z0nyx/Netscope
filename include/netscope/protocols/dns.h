#ifndef NETSCOPE_PROTOCOLS_DNS_H
#define NETSCOPE_PROTOCOLS_DNS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "netscope/protocols/proto_common.h"

#define NS_DNS_HEADER_LEN 12u

#define NS_DNS_MAX_NAME 255u

#define NS_DNS_MAX_JUMPS 32

#define NS_DNS_MAX_QUESTIONS 4u
#define NS_DNS_MAX_ANSWERS 12u

/* Large enough for the widest rdata rendering: an MX record's "PPPPP NAME"
 * (5-digit preference + space + a full NS_DNS_MAX_NAME-byte name). */
#define NS_DNS_MAX_RDATA_TEXT (NS_DNS_MAX_NAME + 8u)

#define NS_DNS_TYPE_A 1u
#define NS_DNS_TYPE_NS 2u
#define NS_DNS_TYPE_CNAME 5u
#define NS_DNS_TYPE_PTR 12u
#define NS_DNS_TYPE_MX 15u
#define NS_DNS_TYPE_TXT 16u
#define NS_DNS_TYPE_AAAA 28u

typedef struct {
    char name[NS_DNS_MAX_NAME + 1];
    uint16_t type;
    uint16_t qclass;
} ns_dns_question_t;

typedef struct {
    char name[NS_DNS_MAX_NAME + 1];
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;

    char rdata_text[NS_DNS_MAX_RDATA_TEXT];
} ns_dns_record_t;

typedef struct {
    uint16_t transaction_id;
    uint16_t flags;
    bool is_response;

    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;

    size_t decoded_question_count;
    ns_dns_question_t questions[NS_DNS_MAX_QUESTIONS];

    size_t decoded_answer_count;
    ns_dns_record_t answers[NS_DNS_MAX_ANSWERS];
} ns_dns_info_t;

ns_parse_status_t ns_parse_dns(const uint8_t *data, size_t length, ns_dns_info_t *out);

const char *ns_dns_type_name(uint16_t type, char *buf, size_t buf_len);

#endif
