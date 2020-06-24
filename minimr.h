//
// Created by Philip Tschiemer on 24.06.20.
//

#ifndef MINIMR_DNS_MINIMR_DNS_H
#define MINIMR_DNS_MINIMR_DNS_H

#include <stdint.h>

#define MINIMR_OK       0
#define MINIMR_NOT_OK   1

#define MINIMR_DNS_HDR_SIZE 12

#define MINIMR_DNS_HDR1_QR      0x80    // query (0), reply (1)
#define MINIMR_DNS_HDR1_OPCODE  0x78    // QUERY (standard query, 0), IQUERY (inverse query, 1), STATUS (server status request, 2)
#define MINIMR_DNS_HDR1_AA      0x04    // Authorative Answer (in response)
#define MINIMR_DNS_HDR1_TC      0x02    // TrunCation, message was truncated due to excessive length
#define MINIMR_DNS_HDR1_RD      0x01    // Recursion Desired, client means a recursive query

#define MINIMR_DNS_HDR2_RA      0x80    // Recursion Available, the responding server supports recursion
#define MINIMR_DNS_HDR2_Z       0x70    // zeros (reserved)
#define MINIMR_DNS_HDR2_RCODE   0x0F    // response code: NOERROR (0), FORMERR (1, format error), SERVAIL (2), NXDOMAIN ( 3, nonexistent domain)

#define MINIMR_DNS_HDR1_OPCODE_QUERY    0x00    // standard query (0)
#define MINIMR_DNS_HDR1_OPCODE_IQUERY   0x08    // inverse query (1)
#define MINIMR_DNS_HDR1_OPCODE_STATUS   0x10    // server status request (2)
#define MINIMR_DNS_HDR1_OPCODE_NOTIFY   0x20    // notify (4)
#define MINIMR_DNS_HDR1_OPCODE_UPDATE   0x28    // update (5)
#define MINIMR_DNS_HDR1_OPCODE_DSO      0x30    // DNS Stateful operations (6)

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
#define MINIMR_DNS_HDR2_RCODE_DSOTYPENI 10  // DSA-TYPE not implemented
#define MINIMR_DNS_HDR2_RCODE_BADVERS   16  // bad opt version
#define MINIMR_DNS_HDR2_RCODE_BADSIG    16  // TSIG signature failure
#define MINIMR_DNS_HDR2_RCODE_BADKEY    17  // key not recognized
#define MINIMR_DNS_HDR2_RCODE_BADTIME   18  // signature out of time window
#define MINIMR_DNS_HDR2_RCODE_BADMODE   19  // bad TKEY mode
#define MINIMR_DNS_HDR2_RCODE_BADNAME   20  // duplicate key name
#define MINIMR_DNS_HDR2_RCODE_BAGALG    21  // algorithm not supported
#define MINIMR_DNS_HDR2_RCODE_BADTRUNC  22  // bad truncation
#define MINIMR_DNS_HDR2_RCODE_BADCOOKIE 23  // bad missing server cookie



struct minimr_dns_hdr {
    uint16_t transaction_id; // can be 0x0000

    uint8_t flags[2];

    uint16_t nquestions;
    uint16_t nanswers;
    uint16_t nauthrr;
    uint16_t nextrarr;
};

#define MINIMR_DNS_UNICAST          0x8000  // unicast requested
#define MINIMR_DNS_QCLASS           0x7FFF

#define MINIMR_DNS_QCLASS_IN        0x0001
#define MINIMR_DNS_QCLASS_CH        0x0003
#define MINIMR_DNS_QCLASS_HS        0x0004
#define MINIMR_DNS_QCLASS_NONE      0x00fe
#define MINIMR_DNS_QCLASS_ANY       0x00ff

#define MINIMR_DNS_QTYPE_A           1
#define MINIMR_DNS_QTYPE_AAAA        28
#define MINIMR_DNS_QTYPE_PTR         12
#define MINIMR_DNS_QTYPE_SRV         33
#define MINIMR_DNS_QTYPE_TXT         16

#define MINIMR_DNS_QTYPE_AFSDB       18
#define MINIMR_DNS_QTYPE_APL         42
#define MINIMR_DNS_QTYPE_CAA         257
#define MINIMR_DNS_QTYPE_CDNSKEY     60
#define MINIMR_DNS_QTYPE_CDS         59
#define MINIMR_DNS_QTYPE_CERT        37
#define MINIMR_DNS_QTYPE_CNAME       5
#define MINIMR_DNS_QTYPE_CSYNC       62
#define MINIMR_DNS_QTYPE_DHCID       49
#define MINIMR_DNS_QTYPE_DLV         32769
#define MINIMR_DNS_QTYPE_DNAME       39
#define MINIMR_DNS_QTYPE_DNSKEY      48
#define MINIMR_DNS_QTYPE_DS          43
#define MINIMR_DNS_QTYPE_HINFO       13
#define MINIMR_DNS_QTYPE_HIP         55
#define MINIMR_DNS_QTYPE_IPSECKEY    45
#define MINIMR_DNS_QTYPE_KEY         25
#define MINIMR_DNS_QTYPE_KX          36
#define MINIMR_DNS_QTYPE_LOC         29
#define MINIMR_DNS_QTYPE_MX          15
#define MINIMR_DNS_QTYPE_NAPTR       35
#define MINIMR_DNS_QTYPE_NS          2
#define MINIMR_DNS_QTYPE_NSEC        47
#define MINIMR_DNS_QTYPE_NSEC3       50
#define MINIMR_DNS_QTYPE_NSEC3PARAM  51
#define MINIMR_DNS_QTYPE_OPENGPGKEY  61
#define MINIMR_DNS_QTYPE_RRSIG       46
#define MINIMR_DNS_QTYPE_RP          17
#define MINIMR_DNS_QTYPE_SIG         24
#define MINIMR_DNS_QTYPE_SMIMEA      53
#define MINIMR_DNS_QTYPE_SOA         6
#define MINIMR_DNS_QTYPE_SSHFP       44
#define MINIMR_DNS_QTYPE_TA          32768
#define MINIMR_DNS_QTYPE_TKEY        249
#define MINIMR_DNS_QTYPE_TLSA        52
#define MINIMR_DNS_QTYPE_TSIG        250
#define MINIMR_DNS_QTYPE_URI         256
#define MINIMR_DNS_QTYPE_ZONEMD      63

//#define MINIMR_DNS_QUERY_TYPE(_qname_) \
//    struct { \
//        uint16_t qtype; \
//        uint16_t unicast_qclass; \
//        uint16_t qname_length; \
//        uint8_t qname[sizeof(_qname_)] \
//    }
//
//#define MINIMR_DNS_QUERY_INIT(_qtype_, _unicast_qclass_, _qname_) \
//    { \
//        .qtype = _qtype_, \
//        .unicast_qclass = _unicast_qclass_, \
//        .qname_length = sizeof(_qname_), \
//        .qname = _qname_ \
//    }

struct minimr_dns_query_stat {
    uint16_t type;
    uint16_t unicast_class;

    uint16_t name_length;
    uint8_t * name;
};

#define MINIMR_DNS_NEXT_QUERY(qname_length) (qname_length + 6)

#define MINIMR_DNS_CACHEFLUSH   0x8000  // cache flush requested
#define MINIMR_DNS_RRCLASS      0x07ff

#define MINIMR_DNS_RRTYPE_


struct minimr_dns_rr {
    uint16_t type;
    uint16_t cache_class;
    uint32_t ttl;
    uint16_t dlength;

    uint16_t name_length;

    uint8_t name[];
};


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

uint8_t minimr_dns_stat_query(struct minimr_dns_query_stat *stat, uint8_t * bytes, uint16_t maxlength)
{
    // minlen = QNAME(1)[= "\0"] QTYPE(2) QCLASS(2)
    if (maxlen <= 5){
        return MINIMR_NOT_OK;
    }
    uint16_t length = 0;

    for(; length < maxlen && bytes[length] != '\0'; length++){
        // just looking for the end of qname
        // note: it's not checked wether the qname is correctly formatted
    }

    if (length == 0 || bytes[length] != '\0' || length + 4 > maxlength){
        return MINIMR_NOT_OK;
    }

    stat->qtype = (bytes[length++] << 8) | bytes[length++];
    stat->unicast_qclass = (bytes[length++] << 8) | bytes[length++];

    stat->qname_length = length;
    stat->qname = bytes;

    return MINIMR_OK;
}

//#define MINIMR_DNS_MAX_QUERIES 1

// TODO
void minimr_handle_msg(uint8_t * bytes, uint16_t length){

    if (length < MINIMR_DNS_HDR_SIZE){
        return;
    }

    struct minimr_dns_hdr hdr;

    minimr_dns_ntoh_hdr(&hdr, bytes);

    // no questions? nothing to do!
    if (hdr.nquestions == 0){
        return;
    }

    uint16_t len = MINIMR_DNS_HDR_SIZE;

    for(uint16_t qi = 0; qi < hdr.nquestions; qi++){

        struct minimr_dns_query_stat stat;

        uint8_t res = minimr_dns_stat_query(&stat, &bytes[len], length - len);

        if (res == MINIMR_NOT_OK){
            // we could respond that it was a faulty query..
            return;
        }

        for(uint16_t ri = 0; ri < 1; ri++){
            if (stat.type != rr[ri].type) continue;
            if (stat.unicast_class && MINIMR_DNS_QCLASS != rr[ri].cache_class && MINIMR_DNS_RRCLASS) continue;

            if (stat.name_length != rr[ri].name_length) continue;

            // pretty much a reverse memcmp
            // reverse order would in principle allow for partials..
            uint8_t stop = 0;
            for(int32_t i = stat.name_length - 1; stop == 0 && i > 0; i--){
                if (stat.name[i] != rr[ri].name[i]){
                    stop = 1;
                }
            }

            if (stop) continue;

            // so it's a match and we might consider responding
            // but before we should also check if our response is already known
        }

    }

}

#endif //MINIMR_DNS_MINIMR_DNS_H
