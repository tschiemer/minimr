//
// Created by Philip Tschiemer on 24.06.20.
//
// official definitions that most likely are not needed are just commented out
//

#ifndef MINIMR_MINIMR_H
#define MINIMR_MINIMR_H

#include "minimropt.h"

#ifdef __cplusplus
extern "C" {
#endif


/*************** Generic defines used **************/

#ifndef NULL
#define NULL 0
#endif

#ifndef MINIMR_ASSERT
#define MINIMR_ASSERT(x)
#endif

#ifndef MINIMR_DEBUGF
#define MINIMR_DEBUGF(fmt,...)
#endif


// big endian
//#define MINIMR_NTOHS(__u16__) (__u16__)
//#define MINIMR_NTOHL(__u32__) (__u32__)

// little endian
#define MINIMR_NTOHS(__u16__) ( (((__u16__) & 0xff00 ) >> 8) | (((__u16__) & 0x00ff ) << 8) )
#define MINIMR_NTOHL(__u32__) ( (((__u32__) & 0xff000000 ) >> 24) | (((__u32__) & 0x00ff0000 ) >> 8) | (((__u32__) & 0x0000ff00 ) << 8) | (((__u32__) & 0x000000ff ) << 24) )


#define MINIMR_HTONS(__u16__) MINIMR_NTOHS(__u16__)
#define MINIMR_HTONL(__u16__) MINIMR_NTOHL(__u16__)


/*************** minimr options **************/

#ifndef MINIMR_RR_CUSTOM_FIELD
#define MINIMR_RR_CUSTOM_FIELD
#endif

#if MINIMR_TIMESTAMP_USE == 1

#ifndef MINIMR_TIMESTAMP_TYPE
#error MINIMR_TIMESTAMP_TYPE not defined
#endif

#define MINIMR_TIMESTAMP_FIELD MINIMR_TIMESTAMP_TYPE last_responded;

#else //MINIMR_TIMESTAMP_USE == 0
#define MINIMR_TIMESTAMP_FIELD
#endif


#ifndef MINIMR_COMPRESSION_MAX_JUMPS
#define MINIMR_COMPRESSION_MAX_JUMPS 8
#endif

/*************** minimr function return values  **************/

#define MINIMR_IGNORE           0xff
//#define MINIMR_CONFIG_ERROR     0xfe
//#define MINIMR_BUFFER_OVERFLOW  0xfd


#define MINIMR_OK               0
#define MINIMR_NOT_OK           1

#define MINIMR_RESPOND          2
#define MINIMR_DO_NOT_RESPOND   3

#define MINIMR_CONTINUE         0
#define MINIMR_ABORT            1



/*************** Specified mDNS Values **************/

#define MINIMR_DNS_PROBE_BOOTUP_DELAY_MSEC  250
#define MINIMR_DNS_PROBE_WAIT_MSEC          250


/*************** DNS Definitions **************/
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

#define MINIMR_DNS_CLASS_IN        0x0001
//#define MINIMR_DNS_CLASS_CH        0x0003
//#define MINIMR_DNS_CLASS_HS        0x0004
//#define MINIMR_DNS_CLASS_NONE      0x00fe
#define MINIMR_DNS_CLASS_ANY       0x00ff

#define MINIMR_DNS_TYPE_ANY         255 // wildcard

#define MINIMR_DNS_TYPE_A           1   // ipv4 addr
#define MINIMR_DNS_TYPE_AAAA        28  // ipv6 addr
#define MINIMR_DNS_TYPE_PTR         12  // generic ptr
#define MINIMR_DNS_TYPE_SRV         33  // service
#define MINIMR_DNS_TYPE_TXT         16  // options

// likely not used
#define MINIMR_DNS_TYPE_AFSDB       18
#define MINIMR_DNS_TYPE_APL         42
#define MINIMR_DNS_TYPE_CAA         257
#define MINIMR_DNS_TYPE_CDNSKEY     60
#define MINIMR_DNS_TYPE_CDS         59
#define MINIMR_DNS_TYPE_CERT        37
#define MINIMR_DNS_TYPE_CNAME       5
#define MINIMR_DNS_TYPE_CSYNC       62
#define MINIMR_DNS_TYPE_DHCID       49
#define MINIMR_DNS_TYPE_DLV         32769
#define MINIMR_DNS_TYPE_DNAME       39
#define MINIMR_DNS_TYPE_DNSKEY      48
#define MINIMR_DNS_TYPE_DS          43
#define MINIMR_DNS_TYPE_HINFO       13
#define MINIMR_DNS_TYPE_HIP         55
#define MINIMR_DNS_TYPE_IPSECKEY    45
#define MINIMR_DNS_TYPE_KEY         25
#define MINIMR_DNS_TYPE_KX          36
#define MINIMR_DNS_TYPE_LOC         29
#define MINIMR_DNS_TYPE_MX          15
#define MINIMR_DNS_TYPE_NAPTR       35
#define MINIMR_DNS_TYPE_NS          2
#define MINIMR_DNS_TYPE_NSEC        47
#define MINIMR_DNS_TYPE_NSEC3       50
#define MINIMR_DNS_TYPE_NSEC3PARAM  51
#define MINIMR_DNS_TYPE_OPENGPGKEY  61
#define MINIMR_DNS_TYPE_RRSIG       46
#define MINIMR_DNS_TYPE_RP          17
#define MINIMR_DNS_TYPE_SIG         24
#define MINIMR_DNS_TYPE_SMIMEA      53
#define MINIMR_DNS_TYPE_SOA         6
#define MINIMR_DNS_TYPE_SSHFP       44
#define MINIMR_DNS_TYPE_TA          32768
#define MINIMR_DNS_TYPE_TKEY        249
#define MINIMR_DNS_TYPE_TLSA        52
#define MINIMR_DNS_TYPE_TSIG        250
#define MINIMR_DNS_TYPE_URI         256
#define MINIMR_DNS_TYPE_ZONEMD      63

const uint8_t * minimr_dns_type_tostr(uint16_t type);
uint16_t minimr_dns_type_fromstr(uint8_t * typestr);
const uint8_t * minimr_dns_class_tostr(uint16_t glass);
uint16_t minimr_dns_class_fromstr(uint8_t * classstr);

// Marker of compressed name
#define MINIMR_DNS_COMPRESSED_NAME          0xc0

// Mask for offset (in message) of compressed name
#define MINIMR_DNS_COMPRESSED_NAME_OFFSET    0x3f


/*************** mDNS Header **************/

// header size
#define MINIMR_DNS_HDR_SIZE 12

// flag 1 option masks
#define MINIMR_DNS_HDR1_QR      0x80    // query (0), reply (1)
#define MINIMR_DNS_HDR1_OPCODE  0x78    // QUERY (standard query, 0), IQUERY (inverse query, 1), STATUS (server status request, 2)
#define MINIMR_DNS_HDR1_AA      0x04    // Authorative Answer (in response)
#define MINIMR_DNS_HDR1_TC      0x02    // TrunCation, message was truncated due to excessive length
#define MINIMR_DNS_HDR1_RD      0x01    // Recursion Desired, client means a recursive query

// flag 2 option masks
#define MINIMR_DNS_HDR2_RA      0x80    // Recursion Available, the responding server supports recursion
#define MINIMR_DNS_HDR2_Z       0x70    // zeros (reserved)
#define MINIMR_DNS_HDR2_RCODE   0x0F    // response code: NOERROR (0), FORMERR (1, format error), SERVAIL (2), NXDOMAIN ( 3, nonexistent domain)


// flag 1 QR options
#define MINIMR_DNS_HDR1_QR_QUERY        0x00
#define MINIMR_DNS_HDR1_QR_REPLY        0x80

// flag 1 OPCODE options
// Multicast DNS shall set the OPCODE field to 0 ("standard")
#define MINIMR_DNS_HDR1_OPCODE_QUERY    0x00    // standard query (0)
#define MINIMR_DNS_HDR1_OPCODE_IQUERY   0x08    // inverse query (1)
#define MINIMR_DNS_HDR1_OPCODE_STATUS   0x10    // server status request (2)
#define MINIMR_DNS_HDR1_OPCODE_NOTIFY   0x20    // notify (4)
#define MINIMR_DNS_HDR1_OPCODE_UPDATE   0x28    // update (5)
#define MINIMR_DNS_HDR1_OPCODE_DSO      0x30    // DNS Stateful operations (6)

// flag 2 RCODE options
// MUST be 0 (NOERROR) in multicast message -> to be ignored silently
// other options allowed in unicast messages
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



// direct getters for header fields
#define MINIMR_DNS_HDR_READ_TID(__src__)        ( ((__src__)[0] << 8) | (__src__)[1] )
#define MINIMR_DNS_HDR_READ_FLAG1(__src__)      ( (__src__)[2] )
#define MINIMR_DNS_HDR_READ_FLAG2(__src__)      ( (__src__)[3] )
#define MINIMR_DNS_HDR_READ_NQ(__src__)         ( ((__src__)[4] << 8) | (__src__)[5] )
#define MINIMR_DNS_HDR_READ_NRR(__src__)        ( ((__src__)[6] << 8) | (__src__)[7] )
#define MINIMR_DNS_HDR_READ_NAUTHRR(__src__)    ( ((__src__)[8] << 8) | (__src__)[9] )
#define MINIMR_DNS_HDR_READ_NEXTRARR(__src__)   ( ((__src__)[10] << 8) | (__src__)[11] )

// direct setters for header fields
#define MINIMR_DNS_HDR_WRITE_TID(__dst__, __tid__)              (__dst__)[0] = ((__tid__) >> 8) & 0xff; \
                                                                (__dst__)[1] = (__tid__) & 0xff;
#define MINIMR_DNS_HDR_WRITE_FLAG1(__dst__, __flag1__)          (__dst__)[2] = (__flag1__) & 0xff;
#define MINIMR_DNS_HDR_WRITE_FLAG2(__dst__, __flag2__)          (__dst__)[3] = (__flag2__) & 0xff;
#define MINIMR_DNS_HDR_WRITE_NQ(__dst__, __nq__)                (__dst__)[4] = ((__nq__) >> 8) & 0xff; \
                                                                (__dst__)[5] = (__nq__) & 0xff;
#define MINIMR_DNS_HDR_WRITE_NRR(__dst__, __nrr__)              (__dst__)[6] = ((__nrr__) >> 8) & 0xff; \
                                                                (__dst__)[7] = (__nrr__) & 0xff;
#define MINIMR_DNS_HDR_WRITE_NAUTHRR(__dst__, __nauthrr__)      (__dst__)[8] = ((__nauthrr__) >> 8) & 0xff; \
                                                                (__dst__)[9] = (__nauthrr__) & 0xff;
#define MINIMR_DNS_HDR_WRITE_NEXTRARR(__dst__, __nextrarr__)    (__dst__)[10] = ((__nextrarr__) >> 8) & 0xff; \
                                                                (__dst__)[11] = (__nextrarr__) & 0xff;

// direct getters for all header fields
#define MINIMR_DNS_HDR_READ(__src__, __tid__, __flag1__, __flag2__, __nq__, __nrr__, __nauthrr__, __nextrarr__) \
    (__tid__) = MINIMR_DNS_HDR_READ_TID(__src__); \
    (__flag1__) = MINIMR_DNS_HDR_READ_FLAG1(__src__); \
    (__flag2__) = MINIMR_DNS_HDR_READ_FLAG2(__src__); \
    (__nq__) = MINIMR_DNS_HDR_READ_NQ(__src__); \
    (__nrr__) = MINIMR_DNS_HDR_READ_NRR(__src__); \
    (__nauthrr__) = MINIMR_DNS_HDR_READ_NAUTHRR(__src__); \
    (__nextrarr__) = MINIMR_DNS_HDR_READ_NEXTRARR(__src__);

// direct setter for all header fields
#define MINIMR_DNS_HDR_WRITE(__dst__, __tid__, __flag1__, __flag2__, __nq__, __nrr__, __nauthrr__, __nextrarr__) \
    MINIMR_DNS_HDR_WRITE_TID(__dst__, __tid__) \
    MINIMR_DNS_HDR_WRITE_FLAG1(__dst__, __flag1__) \
    MINIMR_DNS_HDR_WRITE_FLAG2(__dst__, __flag2__) \
    MINIMR_DNS_HDR_WRITE_NQ(__dst__, __nq__) \
    MINIMR_DNS_HDR_WRITE_NRR(__dst__, __nrr__) \
    MINIMR_DNS_HDR_WRITE_NAUTHRR(__dst__, __nauthrr__) \
    MINIMR_DNS_HDR_WRITE_NEXTRARR(__dst__, __nextrarr__)

// writes header for probe query
// __nauthrr__ should be the number of unique RR intended to be used (MUST be sent along with probe query to properly cooperate on tiebreaking)
#define MINIMR_DNS_HDR_WRITE_PROBEQUERY(__dst__, __nq__, __nauthrr__)       MINIMR_DNS_HDR_WRITE(__dst__, MINIMR_DNS_HDR1_QR_QUERY, 0, 0, __nq__, 0, __nauthrr__, 0)

// writes header for standard query
#define MINIMR_DNS_HDR_WRITE_STDQUERY(__dst__, __nq__, __nknownanswers__)   MINIMR_DNS_HDR_WRITE(__dst__, MINIMR_DNS_HDR1_QR_QUERY, 0, 0, __nq__, __nknownanswers__, 0, 0)

// writes header for standard response
#define MINIMR_DNS_HDR_WRITE_STDRESPONSE(__dst__, __nrr__, __nextrarr__)    MINIMR_DNS_HDR_WRITE(__dst__, MINIMR_DNS_HDR1_QR_REPLY,  MINIMR_DNS_HDR1_AA, 0, 0, __nrr__, 0, __nextrarr__ )


/**
 * Comfort header struct
 */
struct minimr_dns_hdr {
    uint16_t transaction_id; // can be 0x0000

    uint8_t flags[2];

    uint16_t nqueries;
    uint16_t nanswers;
    uint16_t nauthrr;
    uint16_t nextrarr;
};

void minimr_dns_hdr_read(struct minimr_dns_hdr *hdr, uint8_t *src);
void minimr_dns_hdr_write(uint8_t *dst, struct minimr_dns_hdr *hdr);

// use defines instead?..
//void minimr_dns_hdr_write_probequery(uint8_t * dst, uint16_t nqueries, uint16_t nauthrr);
//void minimr_dns_hdr_stdquery(uint8_t * dst, uint16_t nqueries, uint16_t nknownanswers);
//void minimr_dns_hdr_stdresponse(uint8_t * dst, uint16_t nrr, uint16_t nauthrr, uint16_t nextrarr);


/*************** mDNS Query **************/

// query masks
#define MINIMR_DNS_QUNICAST          0x8000  // unicast requested
#define MINIMR_DNS_QCLASS           0x7FFF  // mask for qclass

// QNAME(variable) QTYPE(2) QCLASS(2)
#define MINIMR_DNS_Q_SIZE(__namelen__) ( (__namelen__) + 4 )


/**
 * basic query info as computed
 * @see minimr_dns_extract_query_stat()
 **/
struct minimr_dns_query_stat {
    uint16_t type;          // QTYPE
    uint16_t unicast_class; // QUNICAST bit and QCLASS

//    uint16_t name_length;   // computed name length
    uint16_t name_offset;   // offset of name w.r.t message base
    
    // internal usage
    uint16_t match_i;            // record index of matched record (used in processing to avoid reprocessing)
    uint8_t relevant;       //
};

/**
 * extracts query info on success and sets current <pos> after current query
 * @see struct minimr_dns_query_stat
 * @return MINIMR_OK                        if all ok
 * @return MINIMR_NOT_OK                    if query fault occurred
 * @return MINIMR_DNS_HDR2_RCODE_SERVAIL    if server failed (failed to analyze compressed name)
 */
uint8_t minimr_dns_extract_query_stat(struct minimr_dns_query_stat *stat, uint8_t *msg, uint16_t *pos, uint16_t msglen);


#define MINIMR_DNS_Q_WRITE( __dst__, __len__, __name__, __namelen__, __type__, __class__, __unicast_requested__) \
    for(uint16_t i = 0; i < (__namelen__); i++){ (__dst__)[(__len__)+i] = (__name__)[i]; } \
    (__len__) += (__namelen__); \
    (__dst__)[(__len__)++] = ((__type__) >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__type__) & 0xff; \
    (__dst__)[(__len__)++] = ((__class__) | ((__unicast_requested__) & MINIMR_DNS_QUNICAST) >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__class__) & 0xff;

/*************** mDNS RR **************/

#define MINIMR_DNS_CACHEFLUSH   0x8000  // cache flush requested
#define MINIMR_DNS_RRCLASS      0x07ff


// RNAME(variable) RTYPE(2) RCLASS(2) TTL(4) RDLENGTH(2)
#define MINIMR_DNS_RR_SIZE_BASE(__namelen__) ( (__namelen__) + 10 )

#define MINIMR_DNS_RR_A_SIZE(__namelen__)                    (MINIMR_DNS_RR_SIZE_BASE(__namelen__) + 4)
#define MINIMR_DNS_RR_AAAA_SIZE(__namelen__)                 (MINIMR_DNS_RR_SIZE_BASE(__namelen__) + 16)
#define MINIMR_DNS_RR_PTR_SIZE(__namelen__, __domainlen__)   (MINIMR_DNS_RR_SIZE_BASE(__namelen__) + (__domainlen__))
#define MINIMR_DNS_RR_SRV_SIZE(__namelen__, __targetlen__)   (MINIMR_DNS_RR_SIZE_BASE(__namelen__) + 6 + (__targetlen__))
#define MINIMR_DNS_RR_TXT_SIZE(__namelen__, __txtlen__)      (MINIMR_DNS_RR_SIZE_BASE(__namelen__) + (__txtlen__))


/**
 * basic RR info as computed
 * @see minimr_dns_extract_rr_stat()
 */
struct minimr_dns_rr_stat {
    uint16_t type;
    uint16_t cache_class;
    uint32_t ttl;
    uint16_t dlength;

    uint16_t name_length;
    uint16_t name_offset;

    uint16_t data_offset;

    uint8_t match_i; // record index (of matched record or filter)
};

/**
 * extracts RR info on success and sets current <pos> after current RR
 * @see struct minimr_dns_rr_stat
 * @return MINIMR_OK                        if all ok
 * @return MINIMR_NOT_OK                    if query fault occurred
 * @return MINIMR_DNS_HDR2_RCODE_SERVAIL    if server failed (failed to analyze compressed name)
 */
uint8_t minimr_dns_extract_rr_stat(struct minimr_dns_rr_stat *stat, uint8_t *msg, uint16_t *pos, uint16_t msglen);


/**
 * Lexicographic comparison of RRs as used in tiebreaking
 */
int8_t minimr_dns_rr_lexcmp(uint16_t lhsclass, uint16_t lhstype, uint8_t * lhsrdata, uint16_t lhsrdatalen,
                            uint16_t rhsclass, uint16_t rhstype, uint8_t * rhsrdata, uint16_t rhsrdatalen);


#define MINIMR_DNS_RR_WRITE_NAME(__dst__, __len__, __name__, __namelen__) \
    for(uint16_t i = 0; i < (__namelen__); i++){ (__dst__)[(__len__)+i] = (__name__)[i]; } \
    (__len__) += (__namelen__);

//#define MINIMR_DNS_RR_READ_TYPE(__src__)        ( ((__src__)[0] << 8) | (__src__)[1] )

#define MINIMR_DNS_RR_WRITE_TYPE(__dst__, __len__, __type__) \
    (__dst__)[(__len__)++] = ((__type__) >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__type__) & 0xff;


//#define MINIMR_DNS_RR_READ_CACHECLASS(__src__)  ( ((__src__)[0] << 8) | (__src__)[1]

#define MINIMR_DNS_RR_WRITE_CACHECLASS(__dst__, __len__, __cacheclass__) \
    (__dst__)[(__len__)++] = (((__cacheclass__) | MINIMR_DNS_CACHEFLUSH) >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__cacheclass__) & 0xff;

//#define MINIMR_DNS_RR_READ_TTL(__src__)         ( ((__src__)[0] << 24) | ((__src__)[1] << 16) | ((__src__)[2] << 8) | (__src__)[3] )

#define MINIMR_DNS_RR_WRITE_TTL(__dst__, __len__, __ttl__) \
    (__dst__)[(__len__)++] = ((__ttl__) >> 24) & 0xff; \
    (__dst__)[(__len__)++] = ((__ttl__) >> 16) & 0xff; \
    (__dst__)[(__len__)++] = ((__ttl__) >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__ttl__) & 0xff;

#define MINIMR_DNS_RR_WRITE_COMMON(__dst__, __len__, __name__, __namelen__, __type__, __cacheclass__, __ttl__ ) \
    MINIMR_DNS_RR_WRITE_NAME(__dst__, __len__, __name__, __namelen__) \
    MINIMR_DNS_RR_WRITE_TYPE(__dst__, __len__, __type__) \
    MINIMR_DNS_RR_WRITE_CACHECLASS(__dst__, __len__, __cacheclass__) \
    MINIMR_DNS_RR_WRITE_TTL(__dst__, __len__, __ttl__)

// __ipv4__ is assumed uint8_t[4]
#define MINIMR_DNS_RR_WRITE_A_BODY(__dst__, __len__, __ipv4__)  \
    (__dst__)[(__len__)++] = 0; \
    (__dst__)[(__len__)++] = 4; \
    (__dst__)[(__len__)++] = (__ipv4__)[0]; \
    (__dst__)[(__len__)++] = (__ipv4__)[1]; \
    (__dst__)[(__len__)++] = (__ipv4__)[2]; \
    (__dst__)[(__len__)++] = (__ipv4__)[3];

#define MINIMR_DNS_RR_WRITE_A(__dst__, __len__, __name__, __namelen__, __type__, __cacheclass__, __ttl__, __ipv4__) \
    MINIMR_DNS_RR_WRITE_COMMON(__dst__, __len__, __name__, __namelen__, __type__, __cacheclass__, __ttl__) \
    MINIMR_DNS_RR_WRITE_A_BODY(__dst__, __len__, __ipv4__)

// __ipv6__ is assumed uint16_t[8]
#define MINIMR_DNS_RR_WRITE_AAAA_BODY(__dst__, __len__, __ipv6__) \
    (__dst__)[(__len__)++] = 0; \
    (__dst__)[(__len__)++] = 16; \
    (__dst__)[(__len__)++] = ((__ipv6__)[0] >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__ipv6__)[0] & 0xff; \
    (__dst__)[(__len__)++] = ((__ipv6__)[1] >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__ipv6__)[1] & 0xff; \
    (__dst__)[(__len__)++] = ((__ipv6__)[2] >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__ipv6__)[2] & 0xff; \
    (__dst__)[(__len__)++] = ((__ipv6__)[3] >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__ipv6__)[3] & 0xff; \
    (__dst__)[(__len__)++] = ((__ipv6__)[4] >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__ipv6__)[4] & 0xff; \
    (__dst__)[(__len__)++] = ((__ipv6__)[5] >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__ipv6__)[5] & 0xff; \
    (__dst__)[(__len__)++] = ((__ipv6__)[6] >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__ipv6__)[6] & 0xff; \
    (__dst__)[(__len__)++] = ((__ipv6__)[7] >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__ipv6__)[7] & 0xff;

#define MINIMR_DNS_RR_WRITE_AAAA(__dst__, __len__, __name__, __namelen__, __type__, __cacheclass__, __ttl__, __ipv6__) \
    MINIMR_DNS_RR_WRITE_COMMON(__dst__, __len__, __name__, __namelen__, __type__, __cacheclass__, __ttl__) \
    MINIMR_DNS_RR_WRITE_AAAA_BODY(__dst__, __len__, __ipv6__)

// __domain__ is assumed uint8_t[__domainlen__]
#define MINIMR_DNS_RR_WRITE_PTR_BODY(__dst__, __len__, __domain__, __domainlen__) \
    for(uint16_t i = 0; i < (__domainlen__); i++){ (__dst__)[(__len__)+i] = (__domain__)[i]; } \
    (__len__) += __domainlen__;

#define MINIMR_DNS_RR_WRITE_PTR(__dst__, __len__, __name__, __namelen__, __type__, __cacheclass__, __ttl__, __txt__, __txt_len__) \
    MINIMR_DNS_RR_WRITE_COMMON(__dst__, __len__, __name__, __namelen__, __type__, __cacheclass__, __ttl__) \
    MINIMR_DNS_RR_WRITE_PTR_BODY(__dst__, __len__, __txt__, __txt_len__)


// __target__ is assumed uint8_t[__targetlen__]
#define MINIMR_DNS_RR_WRITE_SRV_BODY(__dst__, __len__, __priority__, __weight__, __port__, __target__, __targetlen__) \
    (__dst__)[(__len__)++] = ((__priority__) >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__priority__) & 0xff; \
    (__dst__)[(__len__)++] = ((__weight__) >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__weight__) & 0xff; \
    (__dst__)[(__len__)++] = ((__port__) >> 8) & 0xff; \
    (__dst__)[(__len__)++] = (__port__) & 0xff; \
    for(uint16_t i = 0; i < (__targetlen__); i++){ (__dst__)[(__len__)+i] = (__target__)[i]; } \
    (__len__) += __targetlen__;

#define MINIMR_DNS_RR_WRITE_SRV(__dst__, __len__, __name__, __namelen__, __type__, __cacheclass__, __ttl__, __priority__, __weight__, __port__, __target__, __targetlen__) \
    MINIMR_DNS_RR_WRITE_COMMON(__dst__, __len__, __name__, __namelen__, __type__, __cacheclass__, __ttl__) \
    MINIMR_DNS_RR_WRITE_SRV_BODY(__dst__, __len__, __priority__, __weight__, __port__, __target__, __targetlen__)


// __var_txt__ is assumed uint8_t[__txt_len__]
#define MINIMR_DNS_RR_WRITE_TXT_BODY(__dst__, __len__, __txt__, __txtlen__) \
    for(uint16_t i = 0; i < (__txtlen__); i++){ (__dst__)[(__len__)+i] = (__txt__)[i]; } \
    (__len__) += __txtlen__;

#define MINIMR_DNS_RR_WRITE_TXT(__dst__, __len__, __name__, __namelen__, __type__, __cacheclass__, __ttl__, __txt__, __txtlen__) \
    MINIMR_DNS_RR_WRITE_COMMON(__dst__, __len__, __name__, __namelen__, __type__, __cacheclass__, __ttl__) \
    MINIMR_DNS_RR_WRITE_TXT_BODY(__dst__, __len__, __txt__, __txtlen__)


// forward declaration for minimr_dns_rr_fun
struct minimr_dns_rr;

/**
 * desired function type
 * @see minimr_dns_rr_fun
 */
enum minimr_dns_rr_fun_type {
    minimr_dns_rr_fun_type_respond_to,
    minimr_dns_rr_fun_type_get_rr,
    minimr_dns_rr_fun_type_get_authority_rrs,
    minimr_dns_rr_fun_type_get_extra_rrs,
    minimr_dns_rr_fun_type_get_query
};

#define MINIMR_DNS_RR_FUN_TYPE_IS_VALID( type ) \
    ((type) == minimr_dns_rr_fun_type_respond_to || \
    (type) == minimr_dns_rr_fun_type_get_rr || \
    (type) == minimr_dns_rr_fun_type_get_authority_rrs || \
    (type) == minimr_dns_rr_fun_type_get_extra_rrs || \
    (type) == minimr_dns_rr_fun_type_get_query)

/**
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_is_uptodate, struct minimr_dns_rr * rr, struct minimr_dns_rr_stat * rstat, uint8_t * msg , void * user_data);
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_get_answer_rrs, struct minimr_dns_rr * rr, uint8_t * outmsg, uint16_t * outlen, uint16_t outmsgmaxlen, uint16_t * nrr, void * user_data)
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_get_authority_rrs, .. ) // same as above
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_get_additional_rrs, .. ) // same as above
 */
typedef int (*minimr_dns_rr_fun)(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr *rr, ...);




// Start of named RR struct definer
#define MINIMR_DNS_RR_TYPE_BEGIN_STNAME(__namelen__, __stname__) \
    struct __stname__ { \
        uint16_t type; \
        uint16_t cache_class; \
        uint32_t ttl; \
        \
        MINIMR_TIMESTAMP_FIELD \
        MINIMR_RR_CUSTOM_FIELD \
        \
        minimr_dns_rr_fun fun; \
        \
        uint16_t name_length; \
        \
        uint8_t name[__namelen__];

// Start of anonymous RR struct definer
#define MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) MINIMR_DNS_RR_TYPE_BEGIN_STNAME(__namelen__,)

// End of RR struct definer
#define MINIMR_DNS_RR_TYPE_END() \
    }

/**
 * actual base type definition
 * defines struct minimr_dns_rr
 */
MINIMR_DNS_RR_TYPE_BEGIN_STNAME(,minimr_dns_rr) MINIMR_DNS_RR_TYPE_END();


// A struct fields
#define MINIMR_DNS_RR_TYPE_BODY_A() \
        uint8_t ipv4[4];

// anonymous A RR struct definer
#define MINIMR_DNS_RR_TYPE_A(__namelen__) \
    MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) \
    MINIMR_DNS_RR_TYPE_BODY_A() \
    MINIMR_DNS_RR_TYPE_END()

// AAAA struct fields
#define MINIMR_DNS_RR_TYPE_BODY_AAAA() \
        uint16_t ipv6[8];

// anonymous AAAA RR struct definer
#define MINIMR_DNS_RR_TYPE_AAAA(__namelen__) \
    MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) \
    MINIMR_DNS_RR_TYPE_BODY_AAAA() \
    MINIMR_DNS_RR_TYPE_END()

// PTR struct fields
#define MINIMR_DNS_RR_TYPE_BODY_PTR(__domainlen__) \
        uint16_t domain_length; \
        uint8_t domain[__domainlen__];

// anonymous PTR struct definer
#define MINIMR_DNS_RR_TYPE_PTR(__namelen__, __domainlen__) \
    MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) \
    MINIMR_DNS_RR_TYPE_BODY_PTR(__domainlen__) \
    MINIMR_DNS_RR_TYPE_END()

// SRV struct fields
#define MINIMR_DNS_RR_TYPE_BODY_SRV(__targetlen__) \
        uint16_t priority; \
        uint16_t weight; \
        uint16_t port; \
        uint16_t target_length; \
        uint8_t target[__targetlen__];

// anonymous SRV RR struct definer
#define MINIMR_DNS_RR_TYPE_SRV(__namelen__, __targetlen__) \
    MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) \
    MINIMR_DNS_RR_TYPE_BODY_SRV(__targetlen__) \
    MINIMR_DNS_RR_TYPE_END()

// TXT struct field
#define MINIMR_DNS_RR_TYPE_BODY_TXT(__txtlen__) \
        uint16_t txt_length; \
        uint8_t txt[__txtlen__];

// anonymous TXT RR struct definer
#define MINIMR_DNS_RR_TYPE_TXT(__namelen__, __txtlen__) \
    MINIMR_DNS_RR_TYPE_BEGIN(__namelen__) \
    MINIMR_DNS_RR_TYPE_BODY_TXT(__txtlen__) \
    MINIMR_DNS_RR_TYPE_END()


// if > 0 will typedef minimr_dns_rr_a with given (max) namelen
#if MINIMR_DNS_RR_TYPE_A_DEFAULT_NAMELEN > 0
typedef MINIMR_DNS_RR_TYPE_A(MINIMR_DNS_RR_TYPE_A_DEFAULT_NAMELEN) minimr_dns_rr_a;
#endif

// if > 0 will typedef minimr_dns_rr_aaaa with given (max) namelen
#if MINIMR_DNS_RR_TYPE_AAAA_DEFAULT_NAMELEN > 0
typedef MINIMR_DNS_RR_TYPE_A(MINIMR_DNS_RR_TYPE_A_DEFAULT_NAMELEN) minimr_dns_rr_aaaa;
#endif

// if > 0 will typedef minimr_dns_rr_ptr with given (max) namelen and domainlen
#if MINIMR_DNS_RR_TYPE_PTR_DEFAULT_NAMELEN > 0 && MINIMR_DNS_RR_TYPE_PTR_DEFAULT_DOMAINLEN > 0
typedef MINIMR_DNS_RR_TYPE_A(MINIMR_DNS_RR_TYPE_A_DEFAULT_NAMELEN) minimr_dns_rr_ptr;
#endif

// if > 0 will typedef minimr_dns_rr_srv with given (max) namelen and targetlen
#if MINIMR_DNS_RR_TYPE_SRV_DEFAULT_NAMELEN > 0 && MINIMR_DNS_RR_TYPE_SRV_DEFAULT_TARGETLEN > 0
typedef MINIMR_DNS_RR_TYPE_A(MINIMR_DNS_RR_TYPE_A_DEFAULT_NAMELEN) minimr_dns_rr_;
#endif

// if > 0 will typedef minimr_dns_rr_srv with given (max) namelen and txtlen
#if MINIMR_DNS_RR_TYPE_TXT_DEFAULT_NAMELEN > 0 && MINIMR_DNS_RR_TYPE_TXT_DEFAULT_TXTLEN > 0
typedef MINIMR_DNS_RR_TYPE_A(MINIMR_DNS_RR_TYPE_A_DEFAULT_NAMELEN) minimr_dns_rr_aaa;
#endif



/*************** NAME and general field utilities **************/


/**
 * Turns a NUL-terminated string into N segments preceded by a segment length marker and sets <length> to string length (incl. NUL)
 */
void minimr_dns_normalize_field(uint8_t * field, uint16_t * length, uint8_t marker);

/**
 * Shorthand to normalize an uncompressed NAME
 */
#define minimr_dns_normalize_name(field, length)            minimr_dns_normalize_field(field, length, '.')

/**
 * Shorthand to normalize TXT RDATA
 * length - 1 because length is not NUL-terminated but specifies RDLENGTH
 */
#define minimr_dns_normalize_txt(field, length, marker)     minimr_dns_normalize_field(field, length, marker); \
                                                            if (length != NULL) (*(length))--;

/**
 * Reverse function of minimr_dns_normalize_field()
 * (field must be
 */
void minimr_dns_denormalize_field(uint8_t * field, uint16_t length, uint8_t marker);

//uint8_t minimr_dns_name_len(uint16_t namepos, uint8_t * msg, uint16_t msglen, uint8_t * namelen, uint8_t * bytelen);

/**
 * Lexicographic comparison of two NAMEs where the first MUST be uncompressed and the second CAN be compressed with given message bounds
 */
int32_t minimr_dns_name_cmp(uint8_t * uncompressed_name, uint16_t namepos, uint8_t * msg, uint16_t msglen);

/**
 * Copies possibly compressed name to given destination and returns length of NUL-terminated string
 */
int32_t minimr_dns_uncompress_name(uint8_t * uncompressed_name, uint16_t maxlen, uint16_t namepos, uint8_t * msg, uint8_t msglen);


/*************** Generic framework functions **************/

// Used in RR handler to know in which section the RR is located
// @see minimr_response_handler
typedef enum  {
    minimr_dns_rr_section_answer,
    minimr_dns_rr_section_authority,
    minimr_dns_rr_section_extra
} minimr_dns_rr_section;

struct minimr_filter {
    uint16_t type;
    uint16_t fclass;
    uint8_t * name;
    uint16_t name_length;

};

typedef uint8_t (*minimr_query_handler)(struct minimr_dns_hdr * hdr, struct minimr_dns_query_stat * qstat, uint8_t * msg, uint16_t msglen, void * user_data);
typedef uint8_t (*minimr_rr_handler)(struct minimr_dns_hdr * hdr, minimr_dns_rr_section, struct minimr_dns_rr_stat * rstat, uint8_t * msg, uint16_t msglen, void * user_data);

/**
 * Tries to parse given mDNS message calling the (optional) handlers for each encountered query or RR
 * Can be used to construct a fully featured mDNS responder
 * @var unimulticast    Was message sent over unicast (0)
 * @see minimr_query_handler
 * @see minimr_rr_handler
 */
int32_t minimr_parse_msg(
        uint8_t *msg, uint16_t msglen,
        minimr_query_handler qhandler, struct minimr_filter * qfilters, uint16_t nqfilters,
        minimr_rr_handler rrhandler, struct minimr_filter * rrfilters, uint16_t nrrfilters,
        void * user_data
);

int32_t  minimr_make_msg(
        uint16_t tid, uint8_t flag1, uint8_t flag2,
        struct minimr_dns_rr **records, uint16_t nrecords,
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
        void * user_data
);

/**
 *
 */
uint8_t minimr_announce(
        struct minimr_dns_rr **records, uint16_t nrecords,
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
        void * user_data
);

uint8_t minimr_terminate(
        struct minimr_dns_rr **records, uint16_t nrecords,
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
        void * user_data
);



uint8_t minimr_handle_queries(
    uint8_t *msg, uint16_t msglen,
    struct minimr_dns_query_stat qstats[], uint16_t nqstats,
    struct minimr_dns_rr **records, uint16_t nrecords,
    uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
    uint8_t *unicast_requested
);


#ifdef __cplusplus
}
#endif



#endif //MINIMR_MINIMR_H
