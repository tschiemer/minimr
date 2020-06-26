#include "minimr.h"

#include <iostream>
#include <unistd.h>
#include <cassert>
#include <stdarg.h>

using namespace std;

/***** basic config *****/

#define NQSTATS 10


#define RR_A_NAME ".Where be Kittens.local"
#define RR_A_IPv4 {127, 0, 0, 1}

#define RR_AAAA_NAME ".asdfasdf.local"
#define RR_AAAA_IPv6 {1,2,3,4,5,6,7,8}

#define RR_PTR_NAME "._echo._udp.local"
#define RR_PTR_DOMAIN RR_A_NAME

#define RR_SRV_NAME ".Here be Echoing Kittens._echo._udp.local"
#define RR_SRV_TARGET RR_A_NAME

#define RR_TXT_NAME RR_A_NAME
#define RR_TXT_DATA "//key1=value1//key2=value2//key3=value3"

#define RR_CUSTOM_PTR_NAME "._echo._"
#define RR_CUSTOM_PTR_DOMAIN RR_A_NAME


/***** types *****/

// it can be nice and helpful to actually typedef any RRs instead of using them as anonymous structs (as done below)
// this would be helpful when casting types (and would eliminate the need of the field getter macros that make assumptions about the underlying memory layout)
// this example shows in particular how to add any custom fields

typedef
MINIMR_DNS_RR_TYPE_BEGIN(sizeof(RR_CUSTOM_PTR_NAME))
MINIMR_DNS_RR_TYPE_BODY_PTR(sizeof(RR_CUSTOM_PTR_DOMAIN))
    struct minimr_dns_rr * rr_a;
    struct minimr_dns_rr * rr_srv;
    struct minimr_dns_rr * rr_txt;
MINIMR_DNS_RR_TYPE_END()
Custom_PTR_RR;

/***** function signatures *****/

int generic_rr_handler(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...);
int custom_rr_handler(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...);


// dummy functions
uint16_t receive_udp_packet(uint8_t * payload, uint16_t maxlen);
void send_udp_packet(uint8_t * payload, uint16_t len);

/***** local variables *****/

/* RR config */


MINIMR_DNS_RR_TYPE_A(sizeof(RR_A_NAME)) RR_A = {
    .type = MINIMR_DNS_TYPE_A,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 0xffffffff,
    .fun = generic_rr_handler,
    .name = RR_A_NAME,
    .ipv4 = RR_A_IPv4
};

MINIMR_DNS_RR_TYPE_AAAA(sizeof(RR_AAAA_NAME)) RR_AAAA = {
    .type = MINIMR_DNS_TYPE_AAAA,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = generic_rr_handler,
    .name = RR_AAAA_NAME,
    .ipv6 = RR_AAAA_IPv6
};

MINIMR_DNS_RR_TYPE_PTR(sizeof(RR_PTR_NAME), sizeof(RR_PTR_DOMAIN)) RR_PTR = {
    .type = MINIMR_DNS_TYPE_PTR,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = generic_rr_handler,
    .name = RR_PTR_NAME,
    .domain = RR_PTR_DOMAIN
};

MINIMR_DNS_RR_TYPE_SRV(sizeof(RR_SRV_NAME), sizeof(RR_SRV_TARGET)) RR_SRV = {
    .type = MINIMR_DNS_TYPE_SRV,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = generic_rr_handler,
    .name = RR_PTR_NAME,
    .priority = 1,
    .weight = 100,
    .port = 7,
    .target = RR_SRV_TARGET
};

MINIMR_DNS_RR_TYPE_TXT(sizeof(RR_TXT_NAME), sizeof(RR_TXT_DATA)) RR_TXT = {
    .type = MINIMR_DNS_TYPE_TXT,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = generic_rr_handler,
    .name = RR_TXT_NAME,
    .txt_length = sizeof(RR_TXT_DATA),
    .txt = RR_TXT_DATA
};

Custom_PTR_RR RR_CUSTOM = {
    .type = MINIMR_DNS_TYPE_PTR,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = custom_rr_handler,
    .name = RR_CUSTOM_PTR_NAME,
    .domain_length = sizeof(RR_CUSTOM_PTR_NAME),
    .domain = RR_CUSTOM_PTR_DOMAIN,
    .rr_a = (struct minimr_dns_rr *)&RR_A,
    .rr_srv = (struct minimr_dns_rr *)&RR_PTR,
    .rr_txt = (struct minimr_dns_rr *)&RR_TXT,
};


// being naughty here
struct minimr_dns_rr * records[] = {
    (struct minimr_dns_rr *)&RR_A,
    (struct minimr_dns_rr *)&RR_AAAA,
    (struct minimr_dns_rr *)&RR_PTR,
    (struct minimr_dns_rr *)&RR_SRV,
    (struct minimr_dns_rr *)&RR_TXT,
    (struct minimr_dns_rr *)&RR_CUSTOM,
};

const uint16_t NRECORDS = sizeof(records) / sizeof(struct minimr_dns_rr *);

/***** functions *****/

/** RR callbacks
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_is_uptodate, struct minimr_dns_rr * rr, struct minimr_dns_rr_stat * rstat, uint8_t * msg );
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_get_answer_rrs, struct minimr_dns_rr * rr, uint8_t * outmsg, uint16_t * outlen, uint16_t outmsgmaxlen, uint16_t * nrr)
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_get_authority_rrs, .. ) // same as above
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_get_additional_rrs, .. ) // same as above
 * */

// handlers are only called for RRs that are a direct match
// thus a handler also knows best when to add additional
int generic_rr_handler(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...)
{
    ASSERT(type == minimr_dns_rr_fun_type_is_uptodate || type == minimr_dns_rr_fun_type_get_answer_rrs || type == minimr_dns_rr_fun_type_get_authority_rrs || type == minimr_dns_rr_fun_type_get_additional_rrs);


    if (type == minimr_dns_rr_fun_type_is_uptodate){
        return MINIMR_NOT_UPTODATE;
    }

    // it isn't necessarily safe to put this here

    va_list args;
    va_start(args, rr);

    uint8_t * outmsg = va_arg(args, uint8_t *);
    uint16_t * outmsglen = va_arg(args, uint16_t *);
    uint16_t outmsgmaxlen = va_arg(args, uint16_t);
    uint16_t * nrr = va_arg(args, uint16_t *);

    va_end(args);


    if (type == minimr_dns_rr_fun_type_get_answer_rrs){

        // RNAME(variable len) RTYPE(2) RCLASS(2) TTL(4) RDLENGTH(2) DATA(4)
        if (outmsgmaxlen < rr->name_length + 14){
            return MINIMR_NOT_OK;
        }

        uint16_t l = *outmsglen;

        // helper macros to write all the standard fields of the record
        // you can naturally do this manually and customize it ;)
        
        MINIMR_DNS_RR_WRITE(rr, outmsg, l)

        if (rr->type == MINIMR_DNS_TYPE_A) {
            MINIMR_DNS_RR_WRITE_A_BODY(rr, outmsg, l, MINIMR_DNS_RR_GET_A_IPv4_FIELD(rr))
        }
        else if (rr->type == MINIMR_DNS_TYPE_AAAA) {
            MINIMR_DNS_RR_WRITE_AAAA_BODY(rr, outmsg, l, MINIMR_DNS_RR_GET_AAAA_IPv6_FIELD(rr))
        }
        else if (rr->type == MINIMR_DNS_TYPE_PTR) {
            MINIMR_DNS_RR_WRITE_PTR_BODY(rr, outmsg, l, MINIMR_DNS_RR_GET_PTR_DOMAIN_FIELD(rr), *MINIMR_DNS_RR_GET_PTR_DOMAINLENGTH_FIELD(rr))
        }
        else if (rr->type == MINIMR_DNS_TYPE_SRV) {
            MINIMR_DNS_RR_WRITE_SRV_BODY(rr, outmsg, l, *MINIMR_DNS_RR_GET_SRV_PRIORITY_FIELD(rr), *MINIMR_DNS_RR_GET_SRV_WEIGHT_FIELD(rr), *MINIMR_DNS_RR_GET_SRV_PORT_FIELD(rr), MINIMR_DNS_RR_GET_SRV_TARGET_FIELD(rr), *MINIMR_DNS_RR_GET_SRV_TARGETLENGTH_FIELD(rr))
        }
        else if (rr->type == MINIMR_DNS_TYPE_TXT) {
            MINIMR_DNS_RR_WRITE_TXT_BODY(rr, outmsg, l, MINIMR_DNS_RR_GET_TXT_TXT_FIELD(rr), *MINIMR_DNS_RR_GET_TXT_TXTLENGTH_FIELD(rr))
        }

        *outmsglen = l;
        *nrr = 1;

        DEBUGF("added %d RRs (totlen %d)\n", 1, l);

        return MINIMR_OK;
    }

    if (type == minimr_dns_rr_fun_type_get_authority_rrs){

        DEBUGF("no authority RRs to add\n");

        return MINIMR_OK;
    }

    if (type == minimr_dns_rr_fun_type_get_additional_rrs){

        //
        if (rr->type == MINIMR_DNS_TYPE_PTR){

            // this works only if we have but one service handled by this handler
            // think of something else when you have several services
            static struct minimr_dns_rr * extrarrs[] = {
                    (struct minimr_dns_rr *)&RR_A,
                    (struct minimr_dns_rr *)&RR_AAAA,
                    (struct minimr_dns_rr *)&RR_SRV,
                    (struct minimr_dns_rr *)&RR_TXT,
            };

            const static uint16_t nextrarr = sizeof(extrarrs) / sizeof(struct minimr_dns_rr *);

            uint16_t l = *outmsglen;

            for (int i = 0; i < nextrarr; i++){

                struct minimr_dns_rr * extra = extrarrs[i];

                MINIMR_DNS_RR_WRITE(extra, outmsg, l)

                if (extra->type == MINIMR_DNS_TYPE_A) {
                    MINIMR_DNS_RR_WRITE_A_BODY(extra, outmsg, l, MINIMR_DNS_RR_GET_A_IPv4_FIELD(extra))
                }
                else if (extra->type == MINIMR_DNS_TYPE_AAAA) {
                    MINIMR_DNS_RR_WRITE_AAAA_BODY(extra, outmsg, l, MINIMR_DNS_RR_GET_AAAA_IPv6_FIELD(extra))
                }
                else if (extra->type == MINIMR_DNS_TYPE_PTR) {
                    MINIMR_DNS_RR_WRITE_PTR_BODY(extra, outmsg, l, MINIMR_DNS_RR_GET_PTR_DOMAIN_FIELD(extra), *MINIMR_DNS_RR_GET_PTR_DOMAINLENGTH_FIELD(extra))
                }
                else if (extra->type == MINIMR_DNS_TYPE_SRV) {
                    MINIMR_DNS_RR_WRITE_SRV_BODY(extra, outmsg, l, *MINIMR_DNS_RR_GET_SRV_PRIORITY_FIELD(extra), *MINIMR_DNS_RR_GET_SRV_WEIGHT_FIELD(extra), *MINIMR_DNS_RR_GET_SRV_PORT_FIELD(extra), MINIMR_DNS_RR_GET_SRV_TARGET_FIELD(extra), *MINIMR_DNS_RR_GET_SRV_TARGETLENGTH_FIELD(extra))
                }
                else if (extra->type == MINIMR_DNS_TYPE_TXT) {
                    MINIMR_DNS_RR_WRITE_TXT_BODY(extra, outmsg, l, MINIMR_DNS_RR_GET_TXT_TXT_FIELD(extra), *MINIMR_DNS_RR_GET_TXT_TXTLENGTH_FIELD(extra))
                }

                *nrr ++;
            }

            *outmsglen = l;
        }

        return MINIMR_OK;
    }


    // we could return an OK, but actually we should never reach here
    return MINIMR_NOT_OK;
}

int custom_rr_handler(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...)
{
    ASSERT(type == minimr_dns_rr_fun_type_is_uptodate || type == minimr_dns_rr_fun_type_get_answer_rrs || type == minimr_dns_rr_fun_type_get_authority_rrs || type == minimr_dns_rr_fun_type_get_additional_rrs);

    // as this handler has only been assigned to our custom RR this MUST be true
    ASSERT( rr == (struct minimr_dns_rr *)&RR_CUSTOM );

    Custom_PTR_RR * custom_rr = (Custom_PTR_RR*)rr;

    if (type == minimr_dns_rr_fun_type_is_uptodate){
        return MINIMR_NOT_UPTODATE;
    }


    // now this is a proper guard (but should not be needed if we assume the best)
    if (type != minimr_dns_rr_fun_type_get_answer_rrs && type != minimr_dns_rr_fun_type_get_authority_rrs && type != minimr_dns_rr_fun_type_get_additional_rrs){
        return MINIMR_NOT_OK;
    }

    va_list args;
    va_start(args, rr);

    uint8_t * outmsg = va_arg(args, uint8_t *);
    uint16_t * outmsglen = va_arg(args, uint16_t *);
    uint16_t outmsgmaxlen = va_arg(args, uint16_t);
    uint16_t * nrr = va_arg(args, uint16_t *);

    va_end(args);


    uint16_t l = *outmsglen;

    if (type == minimr_dns_rr_fun_type_get_answer_rrs){


        // RNAME(variable len) RTYPE(2) RCLASS(2) TTL(4) RDLENGTH(2) DATA(4)
        if (outmsgmaxlen < rr->name_length + 14){
            return MINIMR_NOT_OK;
        }


        // shorthand for:
        // MINIMR_DNS_RR_WRITE(rr, outmsg, l)
        // MINIMR_DNS_RR_WRITE_PTR_BODY(rr, outmsg, l, MINIMR_DNS_RR_GET_A_IPv4_FIELD(rr))

        MINIMR_DNS_RR_WRITE_PTR(rr, outmsg, l, custom_rr->domain, custom_rr->domain_length)

        DEBUGF("added %d RRs (totlen %d)\n", 1, l);

        return MINIMR_OK;
    }


    if (type == minimr_dns_rr_fun_type_get_additional_rrs) {

        MINIMR_DNS_RR_WRITE_A(custom_rr->rr_a, outmsg, l, MINIMR_DNS_RR_GET_A_IPv4_FIELD(custom_rr->rr_a))

        MINIMR_DNS_RR_WRITE_TXT(custom_rr->rr_txt, outmsg, l, MINIMR_DNS_RR_GET_TXT_TXT_FIELD(custom_rr->rr_txt), *MINIMR_DNS_RR_GET_TXT_TXTLENGTH_FIELD(custom_rr->rr_txt))

        MINIMR_DNS_RR_WRITE_SRV(custom_rr->rr_srv, outmsg, l, *MINIMR_DNS_RR_GET_SRV_PRIORITY_FIELD(custom_rr->rr_srv), *MINIMR_DNS_RR_GET_SRV_WEIGHT_FIELD(custom_rr->rr_srv), *MINIMR_DNS_RR_GET_SRV_PORT_FIELD(custom_rr->rr_srv), MINIMR_DNS_RR_GET_SRV_TARGET_FIELD(custom_rr->rr_srv), *MINIMR_DNS_RR_GET_SRV_TARGETLENGTH_FIELD(custom_rr->rr_srv))

        *nrr += 3;

    }

    *outmsglen = l;

    return MINIMR_OK;
}

/* other functions */

uint16_t receive_udp_packet(uint8_t * payload, uint16_t maxlen){

    assert(payload != NULL);
    assert(maxlen > 0);

    size_t r = fread(payload, sizeof(uint8_t), maxlen, stdin);

//    if (r > 0){
//        DEBUGF("read %lu bytes\n", r);
//    }

    return r;
}

void send_udp_packet(uint8_t * payload, uint16_t len){

    if (len == 0){
        return;
    }


    fwrite(payload, sizeof(uint8_t), len, stdout);
    fflush(stdout);
}

int main() {



    for (int i = 0; i < NRECORDS; i++){
        minimr_dns_normalize_name(records[i]);

        if (records[i]->type == MINIMR_DNS_TYPE_TXT){
            
            // NOTE: MINIMR_DNS_RR_GET_TXT_FIELD makes assumptions about memory layout (when using predefined type)
            minimr_dns_normalize_txt(MINIMR_DNS_RR_GET_TXT_TXT_FIELD(records[i]));
        }
    }

    struct minimr_dns_query_stat qstats[NQSTATS];


    while(!feof(stdin)){

        uint8_t in[2048];
        uint16_t inlen = 0;

        inlen = receive_udp_packet(in, sizeof(in));

        if (inlen == 0){
            continue;
        }

        uint8_t out[2048];
        uint16_t outlen = 0;

        uint8_t res = minimr_handle_msg(in, inlen, qstats, NQSTATS, records, NRECORDS, out, &outlen, sizeof(out));

        if (res == MINIMR_IGNORE){
            // it's not a message we should bother about
            DEBUGF("MINIMR_IGNORE\n");
            continue;
        }

        if (res == MINIMR_DNS_HDR2_RCODE_FORMERR){
            // we could send a response to the querying device with this result code
            // don't do this if it was a multicast
            DEBUGF("MINIMR_DNS_HDR2_RCODE_FORMERR\n");
            continue;
        }

        if (res == MINIMR_DNS_HDR2_RCODE_SERVAIL){
            // we could send a response to the querying device with this result code
            // don't do this if it was a multicast
            DEBUGF("MINIMR_DNS_HDR2_RCODE_SERVAIL\n");
            continue;
        }

        if (res != MINIMR_DNS_HDR2_RCODE_NOERROR){
            // just a last test for safety
            DEBUGF("other error!\n");
            continue;
        }

        DEBUGF("MINIMR_DNS_HDR2_RCODE_NOERROR\n");

        send_udp_packet(out, outlen);


    }


    return 0;
}