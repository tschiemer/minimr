//
// Created by Philip Tschiemer on 24.06.20.
//
// official definitions that most likely are not needed are just commented out
//

#ifndef MINIMR_DNS_MINIMR_DNS_H
#define MINIMR_DNS_MINIMR_DNS_H

#include "minimropt.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NULL
#define NULL 0
#endif

#ifndef MINIMR_ASSERT
#define MINIMR_ASSERT(x)
#endif

#ifndef MINIMR_DEBUGF
#define MINIMR_DEBUGF(fmt,...)
#endif

#ifndef MINIMR_DNS_TXT_MARKER1
#define MINIMR_DNS_TXT_MARKER1 '.'
#endif

#ifndef MINIMR_DNS_TXT_MARKER2
#define MINIMR_DNS_TXT_MARKER2 '.'
#endif

#ifndef MINIMR_DNS_RR_A_IPv4_PTR_OFFSET
#define MINIMR_DNS_RR_A_IPv4_PTR_OFFSET 0
#endif

#ifndef MINIMR_DNS_RR_AAAA_IPv6_PTR_OFFSET
#define MINIMR_DNS_RR_AAAA_IPv6_PTR_OFFSET 0
#endif

#ifndef MINIMR_DNS_RR_PTR_DOMAINLEN_PTR_OFFSET
#define MINIMR_DNS_RR_PTR_DOMAINLEN_PTR_OFFSET 0
#endif
#ifndef MINIMR_DNS_RR_PTR_DOMAIN_PTR_OFFSET
#define MINIMR_DNS_RR_PTR_DOMAIN_PTR_OFFSET 2
#endif

#ifndef MINIMR_DNS_RR_SRV_PRIORITY_PTR_OFFSET
#define MINIMR_DNS_RR_SRV_PRIORITY_PTR_OFFSET 0
#endif
#ifndef MINIMR_DNS_RR_SRV_WEIGHT_PTR_OFFSET
#define MINIMR_DNS_RR_SRV_WEIGHT_PTR_OFFSET 2
#endif
#ifndef MINIMR_DNS_RR_SRV_PORT_PTR_OFFSET
#define MINIMR_DNS_RR_SRV_PORT_PTR_OFFSET 4
#endif
#ifndef MINIMR_DNS_RR_SRV_TARGETLEN_PTR_OFFSET
#define MINIMR_DNS_RR_SRV_TARGETLEN_PTR_OFFSET 6
#endif
#ifndef MINIMR_DNS_RR_SRV_TARGET_PTR_OFFSET
#define MINIMR_DNS_RR_SRV_TARGET_PTR_OFFSET 8
#endif

#ifndef MINIMR_DNS_RR_TXT_TXTLEN_PTR_OFFSET
#define MINIMR_DNS_RR_TXT_TXTLEN_PTR_OFFSET 0
#endif
#ifndef MINIMR_DNS_RR_TXT_TXT_PTR_OFFSET
#define MINIMR_DNS_RR_TXT_TXT_PTR_OFFSET 2
#endif


#define MINIMR_IGNORE           0xff
#define MINIMR_CONFIG_ERROR     0xfe
#define MINIMR_BUFFER_OVERFLOW  0xfd


#define MINIMR_OK           0
#define MINIMR_NOT_OK       1

#define MINIMR_UPTODATE         2
#define MINIMR_NOT_UPTODATE     3


#define MINIMR_DNS_HDR_SIZE 12

#define MINIMR_DNS_HDR1_QR      0x80    // query (0), reply (1)
#define MINIMR_DNS_HDR1_OPCODE  0x78    // QUERY (standard query, 0), IQUERY (inverse query, 1), STATUS (server status request, 2)
#define MINIMR_DNS_HDR1_AA      0x04    // Authorative Answer (in response)
#define MINIMR_DNS_HDR1_TC      0x02    // TrunCation, message was truncated due to excessive length
#define MINIMR_DNS_HDR1_RD      0x01    // Recursion Desired, client means a recursive query

#define MINIMR_DNS_HDR2_RA      0x80    // Recursion Available, the responding server supports recursion
#define MINIMR_DNS_HDR2_Z       0x70    // zeros (reserved)
#define MINIMR_DNS_HDR2_RCODE   0x0F    // response code: NOERROR (0), FORMERR (1, format error), SERVAIL (2), NXDOMAIN ( 3, nonexistent domain)

#define MINIMR_DNS_HDR1_QR_QUERY        0x00
#define MINIMR_DNS_HDR1_QR_REPLY        0x80

#define MINIMR_DNS_HDR1_OPCODE_QUERY    0x00    // standard query (0)
//#define MINIMR_DNS_HDR1_OPCODE_IQUERY   0x08    // inverse query (1)
//#define MINIMR_DNS_HDR1_OPCODE_STATUS   0x10    // server status request (2)
#define MINIMR_DNS_HDR1_OPCODE_NOTIFY   0x20    // notify (4)
#define MINIMR_DNS_HDR1_OPCODE_UPDATE   0x28    // update (5)
//#define MINIMR_DNS_HDR1_OPCODE_DSO      0x30    // DNS Stateful operations (6)

#define MINIMR_DNS_HDR2_RCODE_NOERROR   0   // ok (0)
#define MINIMR_DNS_HDR2_RCODE_FORMERR   1   // format error (1)
#define MINIMR_DNS_HDR2_RCODE_SERVAIL   2   // server fail (2)
#define MINIMR_DNS_HDR2_RCODE_NXDOMAIN  3   // nonexistent domain (3)
#define MINIMR_DNS_HDR2_RCODE_NOTIMP    4   // not implemented (4)
#define MINIMR_DNS_HDR2_RCODE_REFUSED   5   // refused (5)
#define MINIMR_DNS_HDR2_RCODE_YXDOMAIN  6   // name exists when it should not
#define MINIMR_DNS_HDR2_RCODE_YXRRSET   7   // RR set exists when it should not
#define MINIMR_DNS_HDR2_RCODE_NXRRSET   8   // RR set that should exist does not
#define MINIMR_DNS_HDR2_RCODE_NOTAUTH   9   // not authorizezd / server not authoritaive for zone


struct minimr_dns_hdr {
    uint16_t transaction_id; // can be 0x0000

    uint8_t flags[2];

    uint16_t nquestions;
    uint16_t nanswers;
    uint16_t nauthrr;
    uint16_t nextrarr;
};

#define MINIMR_DNS_UNICAST          0x8000  // unicast requested
#define MINIMR_DNS_QCLASS           0x7FFF  // mask for qclass

#define MINIMR_DNS_CLASS_IN        0x0001
//#define MINIMR_DNS_CLASS_CH        0x0003
//#define MINIMR_DNS_CLASS_HS        0x0004
//#define MINIMR_DNS_CLASS_NONE      0x00fe
#define MINIMR_DNS_CLASS_ANY       0x00ff

#define MINIMR_DNS_TYPE_A           1   // ipv4 addr
#define MINIMR_DNS_TYPE_AAAA        28  // ipv6 addr
#define MINIMR_DNS_TYPE_PTR         12  // generic ptr
#define MINIMR_DNS_TYPE_SRV         33  // service
#define MINIMR_DNS_TYPE_TXT         16  // options

// likely irrelevant
//#define MINIMR_DNS_TYPE_AFSDB       18
//#define MINIMR_DNS_TYPE_APL         42
//#define MINIMR_DNS_TYPE_CAA         257
//#define MINIMR_DNS_TYPE_CDNSKEY     60
//#define MINIMR_DNS_TYPE_CDS         59
//#define MINIMR_DNS_TYPE_CERT        37
//#define MINIMR_DNS_TYPE_CNAME       5
//#define MINIMR_DNS_TYPE_CSYNC       62
//#define MINIMR_DNS_TYPE_DHCID       49
//#define MINIMR_DNS_TYPE_DLV         32769
//#define MINIMR_DNS_TYPE_DNAME       39
//#define MINIMR_DNS_TYPE_DNSKEY      48
//#define MINIMR_DNS_TYPE_DS          43
//#define MINIMR_DNS_TYPE_HINFO       13
//#define MINIMR_DNS_TYPE_HIP         55
//#define MINIMR_DNS_TYPE_IPSECKEY    45
//#define MINIMR_DNS_TYPE_KEY         25
//#define MINIMR_DNS_TYPE_KX          36
//#define MINIMR_DNS_TYPE_LOC         29
//#define MINIMR_DNS_TYPE_MX          15
//#define MINIMR_DNS_TYPE_NAPTR       35
//#define MINIMR_DNS_TYPE_NS          2
//#define MINIMR_DNS_TYPE_NSEC        47
//#define MINIMR_DNS_TYPE_NSEC3       50
//#define MINIMR_DNS_TYPE_NSEC3PARAM  51
//#define MINIMR_DNS_TYPE_OPENGPGKEY  61
//#define MINIMR_DNS_TYPE_RRSIG       46
//#define MINIMR_DNS_TYPE_RP          17
//#define MINIMR_DNS_TYPE_SIG         24
//#define MINIMR_DNS_TYPE_SMIMEA      53
//#define MINIMR_DNS_TYPE_SOA         6
//#define MINIMR_DNS_TYPE_SSHFP       44
//#define MINIMR_DNS_TYPE_TA          32768
//#define MINIMR_DNS_TYPE_TKEY        249
//#define MINIMR_DNS_TYPE_TLSA        52
//#define MINIMR_DNS_TYPE_TSIG        250
//#define MINIMR_DNS_TYPE_URI         256
//#define MINIMR_DNS_TYPE_ZONEMD      63

struct minimr_dns_query_stat {
    uint16_t type;
    uint16_t unicast_class;

    uint16_t name_length;

    uint16_t name_offset; // used for compressed name lookups
    uint16_t ir; // record index of matched record (used in processing to avoid reprocessing)
    uint8_t relevant; //
};

#define MINIMR_DNS_CACHEFLUSH   0x8000  // cache flush requested
#define MINIMR_DNS_RRCLASS      0x07ff

#define MINIMR_DNS_COMPRESSED_NAME          0xc0
#define MINIMR_DNS_COMPRESSED_NAME_OFFSET    0x3f

struct minimr_dns_rr_stat {
    uint16_t type;
    uint16_t cache_class;
    uint32_t ttl;
    uint16_t dlength;

    uint16_t name_length;
    uint16_t name_offset;

    uint16_t data_offset;
};


enum minimr_dns_rr_fun_type {
    minimr_dns_rr_fun_type_is_uptodate,
    minimr_dns_rr_fun_type_get_answer_rrs,
    minimr_dns_rr_fun_type_get_authority_rrs,
    minimr_dns_rr_fun_type_get_additional_rrs
};

// forward declaration for minimr_dns_rr_fun
struct minimr_dns_rr;

/**
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_is_uptodate, struct minimr_dns_rr * rr, struct minimr_dns_rr_stat * rstat, uint8_t * msg );
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_get_answer_rrs, struct minimr_dns_rr * rr, uint8_t * outmsg, uint16_t * outlen, uint16_t outmsgmaxlen, uint16_t * nrr)
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_get_authority_rrs, .. ) // same as above
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_get_additional_rrs, .. ) // same as above
 */
typedef int (*minimr_dns_rr_fun)(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr *rr, ...);

struct minimr_dns_rr {
    uint16_t type;
    uint16_t cache_class;
    uint32_t ttl;

    minimr_dns_rr_fun fun;

    uint16_t name_length;

    uint8_t name[];
};

// RNAME(variable) RTYPE(2) RCLASS(2) TTL(4) RDLENGTH(2)
#define MINIMR_DNS_RR_SIZE_BASE(__rr_ptr__) ( (__rr_ptr__)->name_length + 10 )

#define MINIMR_DNS_RR_A_SIZE(__rr_ptr__)                    (MINIMR_DNS_RR_SIZE_BASE(__rr_ptr__) + 4)
#define MINIMR_DNS_RR_AAAA_SIZE(__rr_ptr__)                 (MINIMR_DNS_RR_SIZE_BASE(__rr_ptr__) + 16)
#define MINIMR_DNS_RR_PTR_SIZE(__rr_ptr__, __domainlen__)   (MINIMR_DNS_RR_SIZE_BASE(__rr_ptr__) + (__domainlen__))
#define MINIMR_DNS_RR_SRV_SIZE(__rr_ptr__, __targetlen__)   (MINIMR_DNS_RR_SIZE_BASE(__rr_ptr__) + 6 + (__targetlen__))
#define MINIMR_DNS_RR_TXT_SIZE(__rr_ptr__, __txtlen__)      (MINIMR_DNS_RR_SIZE_BASE(__rr_ptr__) + (__txtlen__))



// identical memory layout as struct minimr_dns_rr
#define MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) \
    struct { \
        uint16_t type; \
        uint16_t cache_class; \
        uint32_t ttl; \
        \
        minimr_dns_rr_fun fun; \
        \
        uint16_t name_length; \
        \
        uint8_t name[__namelen__];

#define MINIMR_DNS_RR_TYPE_BODY_A() \
        uint8_t ipv4[4];

#define MINIMR_DNS_RR_TYPE_BODY_AAAA() \
        uint16_t ipv6[8];

#define MINIMR_DNS_RR_TYPE_BODY_PTR(__domainlen__) \
        uint16_t domain_length; \
        uint8_t domain[__domainlen__];


#define MINIMR_DNS_RR_TYPE_BODY_SRV(__targetlen__) \
        uint16_t priority; \
        uint16_t weight; \
        uint16_t port; \
        uint16_t target_length; \
        uint8_t target[__targetlen__];


#define MINIMR_DNS_RR_TYPE_BODY_TXT(__txtlen__) \
        uint16_t txt_length; \
        uint8_t txt[__txtlen__];


#define MINIMR_DNS_RR_TYPE_END() \
    }

#define MINIMR_DNS_RR_TYPE_A(__namelen__) \
    MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) \
    MINIMR_DNS_RR_TYPE_BODY_A() \
    MINIMR_DNS_RR_TYPE_END()

#define MINIMR_DNS_RR_TYPE_AAAA(__namelen__) \
    MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) \
    MINIMR_DNS_RR_TYPE_BODY_AAAA() \
    MINIMR_DNS_RR_TYPE_END()

#define MINIMR_DNS_RR_TYPE_PTR(__namelen__, __domainlen__) \
    MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) \
    MINIMR_DNS_RR_TYPE_BODY_PTR(__domainlen__) \
    MINIMR_DNS_RR_TYPE_END()

#define MINIMR_DNS_RR_TYPE_SRV(__namelen__, __targetlen__) \
    MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) \
    MINIMR_DNS_RR_TYPE_BODY_SRV(__targetlen__) \
    MINIMR_DNS_RR_TYPE_END()

#define MINIMR_DNS_RR_TYPE_TXT(__namelen__, __txtlen__) \
    MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) \
    MINIMR_DNS_RR_TYPE_BODY_TXT(__txtlen__) \
    MINIMR_DNS_RR_TYPE_END()


// NOTE: these getters make assumptions about the position in memory
#define MINIMR_DNS_RR_A_GET_IPv4_PTR(__rr_ptr__) ((uint8_t*) &(__rr_ptr__)->name[(__rr_ptr__)->name_length + MINIMR_DNS_RR_A_IPv4_PTR_OFFSET] )

#define MINIMR_DNS_RR_AAAA_GET_IPv6_PTR(__rr_ptr__) ( (uint16_t*)&(__rr_ptr__)->name[(__rr_ptr__)->name_length + MINIMR_DNS_RR_AAAA_IPv6_PTR_OFFSET] )

#define MINIMR_DNS_RR_PTR_GET_DOMAINLEN_PTR(__rr_ptr__) ( (uint16_t*)&(__rr_ptr__)->name[(__rr_ptr__)->name_length + MINIMR_DNS_RR_PTR_DOMAINLEN_PTR_OFFSET] )
#define MINIMR_DNS_RR_PTR_GET_DOMAIN_PTR(__rr_ptr__) ( (uint8_t*)&(__rr_ptr__)->name[(__rr_ptr__)->name_length + MINIMR_DNS_RR_PTR_DOMAIN_PTR_OFFSET] )

#define MINIMR_DNS_RR_SRV_GET_PRIORITY_PTR(__rr_ptr__) ( (uint16_t*)&(__rr_ptr__)->name[(__rr_ptr__)->name_length + MINIMR_DNS_RR_SRV_PRIORITY_PTR_OFFSET] )
#define MINIMR_DNS_RR_SRV_GET_WEIGHT_PTR(__rr_ptr__) ( (uint16_t*)&(__rr_ptr__)->name[(__rr_ptr__)->name_length + MINIMR_DNS_RR_SRV_WEIGHT_PTR_OFFSET] )
#define MINIMR_DNS_RR_SRV_GET_PORT_PTR(__rr_ptr__) ( (uint16_t*)&(__rr_ptr__)->name[(__rr_ptr__)->name_length + MINIMR_DNS_RR_SRV_PORT_PTR_OFFSET] )
#define MINIMR_DNS_RR_SRV_GET_TARGETLEN_PTR(__rr_ptr__) ( (uint16_t*)&(__rr_ptr__)->name[(__rr_ptr__)->name_length + MINIMR_DNS_RR_SRV_TARGETLEN_PTR_OFFSET] )
#define MINIMR_DNS_RR_SRV_GET_TARGET_PTR(__rr_ptr__) ( (uint8_t*)&(__rr_ptr__)->name[(__rr_ptr__)->name_length + MINIMR_DNS_RR_SRV_TARGET_PTR_OFFSET] )

#define MINIMR_DNS_RR_TXT_GET_TXTLEN_PTR(__rr_ptr__) ( (uint16_t*)&(__rr_ptr__)->name[(__rr_ptr__)->name_length + MINIMR_DNS_RR_TXT_TXTLEN_PTR_OFFSET] )
#define MINIMR_DNS_RR_TXT_GET_TXT_PTR(__rr_ptr__) ( (uint8_t*)&(__rr_ptr__)->name[(__rr_ptr__)->name_length + MINIMR_DNS_RR_TXT_TXT_PTR_OFFSET] )


#define MINIMR_DNS_RR_WRITE(__rr_ptr__, __var_msg__, __var_len__) \
    for(uint16_t i = 0; i < (__rr_ptr__)->name_length; i++){ (__var_msg__)[(__var_len__)+i] = (__rr_ptr__)->name[i]; } \
    (__var_len__) += (__rr_ptr__)->name_length; \
    (__var_msg__)[(__var_len__)++] = ((__rr_ptr__)->type >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__rr_ptr__)->type & 0xff; \
    (__var_msg__)[(__var_len__)++] = (((__rr_ptr__)->cache_class | MINIMR_DNS_CACHEFLUSH) >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__rr_ptr__)->cache_class & 0xff; \
    (__var_msg__)[(__var_len__)++] = ((__rr_ptr__)->ttl >> 24) & 0xff; \
    (__var_msg__)[(__var_len__)++] = ((__rr_ptr__)->ttl >> 16) & 0xff; \
    (__var_msg__)[(__var_len__)++] = ((__rr_ptr__)->ttl >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__rr_ptr__)->ttl & 0xff;

// __var_ipv4__ is assumed uint8_t[4]
#define MINIMR_DNS_RR_WRITE_A_BODY(__rr_ptr__, __var_msg__, __var_len__, __var_ipv4__)  \
    (__var_msg__)[(__var_len__)++] = 0; \
    (__var_msg__)[(__var_len__)++] = 4; \
    (__var_msg__)[(__var_len__)++] = (__var_ipv4__)[0]; \
    (__var_msg__)[(__var_len__)++] = (__var_ipv4__)[1]; \
    (__var_msg__)[(__var_len__)++] = (__var_ipv4__)[2]; \
    (__var_msg__)[(__var_len__)++] = (__var_ipv4__)[3];

#define MINIMR_DNS_RR_WRITE_A(__rr_ptr__, __var_msg__, __var_len__, __var_ipv4__) \
    MINIMR_DNS_RR_WRITE(__rr_ptr__, __var_msg__, __var_len__) \
    MINIMR_DNS_RR_WRITE_A_BODY(__rr_ptr__, __var_msg__, __var_len__, __var_ipv4__)

// __var_ipv6__ is assumed uint16_t[8]
#define MINIMR_DNS_RR_WRITE_AAAA_BODY(__rr_ptr__, __var_msg__, __var_len__, __var_ipv6__) \
    (__var_msg__)[(__var_len__)++] = 0; \
    (__var_msg__)[(__var_len__)++] = 16; \
    (__var_msg__)[(__var_len__)++] = ((__var_ipv6__)[0] >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__var_ipv6__)[0] & 0xff; \
    (__var_msg__)[(__var_len__)++] = ((__var_ipv6__)[1] >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__var_ipv6__)[1] & 0xff; \
    (__var_msg__)[(__var_len__)++] = ((__var_ipv6__)[2] >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__var_ipv6__)[2] & 0xff; \
    (__var_msg__)[(__var_len__)++] = ((__var_ipv6__)[3] >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__var_ipv6__)[3] & 0xff; \
    (__var_msg__)[(__var_len__)++] = ((__var_ipv6__)[4] >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__var_ipv6__)[4] & 0xff; \
    (__var_msg__)[(__var_len__)++] = ((__var_ipv6__)[5] >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__var_ipv6__)[5] & 0xff; \
    (__var_msg__)[(__var_len__)++] = ((__var_ipv6__)[6] >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__var_ipv6__)[6] & 0xff; \
    (__var_msg__)[(__var_len__)++] = ((__var_ipv6__)[7] >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__var_ipv6__)[7] & 0xff;

#define MINIMR_DNS_RR_WRITE_AAAA(__rr_ptr__, __var_msg__, __var_len__, __var_ipv6__) \
    MINIMR_DNS_RR_WRITE(__rr_ptr__, __var_msg__, __var_len__) \
    MINIMR_DNS_RR_WRITE_AAAA_BODY(__rr_ptr__, __var_msg__, __var_len__, __var_ipv6__)

// __var_domain__ is assumed uint8_t[__domain_len__]
#define MINIMR_DNS_RR_WRITE_PTR_BODY(__rr_ptr__, __var_msg__, __var_len__, __var_domain__, __domain_len__) \
    for(uint16_t i = 0; i < (__domain_len__); i++){ (__var_msg__)[(__var_len__)+i] = (__var_domain__)[i]; } \
    (__var_len__) += __domain_len__;

#define MINIMR_DNS_RR_WRITE_PTR(__rr_ptr__, __var_msg__, __var_len__, __var_txt__, __txt_len__) \
    MINIMR_DNS_RR_WRITE(__rr_ptr__, __var_msg__, __var_len__) \
    MINIMR_DNS_RR_WRITE_PTR_BODY(__rr_ptr__, __var_msg__, __var_len__, __var_txt__, __txt_len__)


// __var_txt__ is assumed uint8_t[__var_txt__]
#define MINIMR_DNS_RR_WRITE_SRV_BODY(__rr_ptr__, __var_msg__, __var_len__, __priority__, __weight__, __port__, __var_target__, __targetlen__) \
    (__var_msg__)[(__var_len__)++] = ((__priority__) >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__priority__) & 0xff; \
    (__var_msg__)[(__var_len__)++] = ((__weight__) >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__weight__) & 0xff; \
    (__var_msg__)[(__var_len__)++] = ((__port__) >> 8) & 0xff; \
    (__var_msg__)[(__var_len__)++] = (__port__) & 0xff; \
    for(uint16_t i = 0; i < (__targetlen__); i++){ (__var_msg__)[(__var_len__)+i] = (__var_target__)[i]; } \
    (__var_len__) += __targetlen__;

#define MINIMR_DNS_RR_WRITE_SRV(__rr_ptr__, __var_msg__, __var_len__, __priority__, __weight__, __port__, __var_target__, __targetlen__) \
    MINIMR_DNS_RR_WRITE(__rr_ptr__, __var_msg__, __var_len__) \
    MINIMR_DNS_RR_WRITE_SRV_BODY(__rr_ptr__, __var_msg__, __var_len__, __priority__, __weight__, __port__, __var_target__, __targetlen__)


// __var_txt__ is assumed uint8_t[__txt_len__]
#define MINIMR_DNS_RR_WRITE_TXT_BODY(__rr_ptr__, __var_msg__, __var_len__, __var_txt__, __txt_len__) \
    for(uint16_t i = 0; i < (__txt_len__); i++){ (__var_msg__)[(__var_len__)+i] = (__var_txt__)[i]; } \
    (__var_len__) += __txt_len__;

#define MINIMR_DNS_RR_WRITE_TXT(__rr_ptr__, __var_msg__, __var_len__, __var_txt__, __txt_len__) \
    MINIMR_DNS_RR_WRITE(__rr_ptr__, __var_msg__, __var_len__) \
    MINIMR_DNS_RR_WRITE_TXT_BODY(__rr_ptr__, __var_msg__, __var_len__, __var_txt__, __txt_len__)


void minimr_dns_ntoh_hdr(struct minimr_dns_hdr *hdr, uint8_t *bytes);
void minimr_dns_hton_hdr(uint8_t *bytes, struct minimr_dns_hdr *hdr);


void minimr_dns_normalize_field(uint8_t * field, uint16_t * length, uint8_t marker);

#define minimr_dns_normalize_name(field, length) minimr_dns_normalize_field(field, length, '.')

// length - 1 because
#define minimr_dns_normalize_txt(field, length, marker) \
    do { \
        minimr_dns_normalize_field(field, length, marker); \
        if (length != NULL) (*(length))--; \
    } while(0);

uint8_t minimr_dns_extract_query_stat(struct minimr_dns_query_stat *stat, uint8_t *msg, uint16_t *pos, uint16_t msglen);

uint8_t minimr_dns_extract_rr_stat(struct minimr_dns_rr_stat *stat, uint8_t *msg, uint16_t *pos, uint16_t msglen);

uint8_t minimr_handle_msg(
    uint8_t *msg, uint16_t msglen,
    struct minimr_dns_query_stat stats[], uint16_t nqstats,
    struct minimr_dns_rr **records, uint16_t nrecords,
    uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen
);

uint8_t minimr_announce(
    struct minimr_dns_rr **records, uint16_t nrecords,
    uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen
);


uint8_t minimr_terminate(
        struct minimr_dns_rr **records, uint16_t nrecords,
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen
);

#ifdef __cplusplus
}
#endif



#endif //MINIMR_DNS_MINIMR_DNS_H
