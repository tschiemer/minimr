//
// Created by Philip Tschiemer on 24.06.20.
//
// official definitions that most likely are not needed are just commented out
//

#ifndef MINIMR_DNS_MINIMR_DNS_H
#define MINIMR_DNS_MINIMR_DNS_H

#include <stdint.h>

#ifndef ASSERT
#define ASSERT(x)
#endif

#ifndef MINIMR_DNS_TXT_MARKER1
#define MINIMR_DNS_TXT_MARKER1 '/'
#endif

#ifndef MINIMR_DNS_TXT_MARKER2
#define MINIMR_DNS_TXT_MARKER2 '/'
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

typedef int (*minimr_dns_rr_fun)( enum minimr_dns_rr_fun_type fun, ... );

struct minimr_dns_rr {
    uint16_t type;
    uint16_t cache_class;
    uint32_t ttl;

    minimr_dns_rr_fun fun;

    uint16_t name_length;

    uint8_t name[];
};

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
        uint8_t ip[4];

#define MINIMR_DNS_RR_TYPE_BODY_AAAA() \
        uint16_t ip[8];

#define MINIMR_DNS_RR_TYPE_BODY_PTR(__domainlen__) \
        uint8_t domain[__domainlen__];


#define MINIMR_DNS_RR_TYPE_BODY_SRV(__targetlen__) \
        uint16_t priority; \
        uint16_t weight; \
        uint16_t port; \
        uint8_t target[__targetlen__];


#define MINIMR_DNS_RR_TYPE_BODY_TXT(__txtlen__) \
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
    MINIMR_DNS_RR_TYPE_BODY_PTR( __domainlen__) \
    MINIMR_DNS_RR_TYPE_END()

#define MINIMR_DNS_RR_TYPE_SRV(__namelen__, __targetlen__) \
    MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) \
    MINIMR_DNS_RR_TYPE_BODY_SRV(__targetlen__) \
    MINIMR_DNS_RR_TYPE_END()

#define MINIMR_DNS_RR_TYPE_TXT(__namelen__, __txtlen__) \
    MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) \
    MINIMR_DNS_RR_TYPE_BODY_TXT(__txtlen__) \
    MINIMR_DNS_RR_TYPE_END()


// NOTE: this makes assumptions about the position of the txt field in memory
#define MINIMR_DNS_RR_GET_TXT_FIELD(__rr_txt_ptr__) ( &(__rr_txt_ptr__)->name[(__rr_txt_ptr__)->name_length+1] )


inline void minimr_dns_ntoh_hdr(struct minimr_dns_hdr * hdr, uint8_t * bytes)
{
    hdr->transaction_id = (bytes[0] << 8) | bytes[1];
    hdr->flags[0] = bytes[2];
    hdr->flags[1] = bytes[3];
    hdr->nquestions = (bytes[4] << 8) | bytes[5]; // nquestions
    hdr->nanswers = (bytes[6] << 8) | bytes[7]; // nanswers
    hdr->nauthrr = (bytes[8] << 8) | bytes[9]; // nauthrr
    hdr->nextrarr = (bytes[10] << 8) | bytes[11]; // nextrarr
}

inline void minimr_dns_hton_hdr(uint8_t * bytes, struct minimr_dns_hdr * hdr)
{
    bytes[0] = (hdr->transaction_id >> 8) & 0xff;
    bytes[1] = hdr->transaction_id& 0xff;
    bytes[2] = hdr->flags[0];
    bytes[3] = hdr->flags[1];
    bytes[4] = (hdr->nquestions >> 8) & 0xff;
    bytes[5] = hdr->nquestions & 0xff;
    bytes[6] = (hdr->nanswers >> 8) & 0xff;
    bytes[7] = hdr->nanswers& 0xff;
    bytes[8] = (hdr->nauthrr >> 8) & 0xff;
    bytes[9] = hdr->nauthrr & 0xff;
    bytes[10] = (hdr->nextrarr >> 8) & 0xff;
    bytes[11] = hdr->nextrarr & 0xff;
}

void minimr_dns_normalize_name(struct minimr_dns_rr * rr);
void minimr_dns_normalize_txt(uint8_t * txt);

uint8_t minimr_dns_extract_query_stat(struct minimr_dns_query_stat * stat, uint8_t * msg, uint16_t * pos, uint16_t msglen);
uint8_t minimr_dns_extract_rr_stat(struct minimr_dns_rr_stat * stat, uint8_t * msg, uint16_t *pos, uint16_t msglen);

uint8_t minimr_handle_msg(
        uint8_t * msg, uint16_t msglen,
        struct minimr_dns_query_stat stats[], uint16_t nqstats,
        struct minimr_dns_rr ** records, uint16_t nrecords,
        uint8_t *outmsg, uint16_t * outmsglen, uint16_t outmsgmaxlen
);

#endif //MINIMR_DNS_MINIMR_DNS_H
