#include "minimr.h"

#include <iostream>
#include <unistd.h>
#include <cassert>
#include <stdarg.h>

using namespace std;

/***** basic config *****/

// limits the number of questions we can actually answer
// likely this can be identical to your number of RRs
#define NQSTATS 10

// note: actual names parts MUST be preceeded by a dot character ('.') - at least when you make use of the  minimr_dns_normalize_name() function as below
// otherwise you can encode the length of each following component, such as "\x0fWhere be Kittens\x05local"
// also, the terminating NUL-character '\0' is necessary.

#define RR_A_NAME ".where-be-kittens.local"
// the predefined IPv4 type is an uint8_t[4]
#define RR_A_IPv4 {127, 0, 0, 1}

#define RR_AAAA_NAME ".where-be-kittens.local"
// the predefined IPv6 type is an uint16_t[8]
#define RR_AAAA_IPv6 {1,2,3,4,5,6,7,8}

#define RR_PTR_NAME "._echo._udp.local"
#define RR_PTR_DOMAIN RR_A_NAME

#define RR_SRV_NAME ".Here be Echoing Kittens._echo._udp.local"
#define RR_SRV_TARGET RR_A_NAME

#define RR_TXT_NAME RR_A_NAME
// when using minimr_dns_normalize_field() all key/value pairs must be preceeded by one character to be defined by you
// MUST NOT be the NUL character '\0' which is used to detect the end of the data
#define MY_TXT_MARKER '.'
#define RR_TXT_DATA ".key1=value1.key2=value2.key3=value3"

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
    struct minimr_dns_rr * rr_aaaa;
    struct minimr_dns_rr * rr_txt;
MINIMR_DNS_RR_TYPE_END()
Custom_PTR_RR;

/***** function signatures *****/

static int generic_rr_handler(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...);
static int custom_rr_handler(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...);


// dummy functions
static uint16_t receive_udp_packet(uint8_t * payload, uint16_t maxlen);
static void send_udp_packet(uint8_t * payload, uint16_t len);

/***** local variables *****/

/* RR config */


static MINIMR_DNS_RR_TYPE_A(sizeof(RR_A_NAME)) RR_A = {
    .type = MINIMR_DNS_TYPE_A,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 0xffffffff,
    .fun = generic_rr_handler,
    .name = RR_A_NAME,
    // anything hereafter is not part of the basic struct minimr_dns_rr
    .ipv4 = RR_A_IPv4
};

static MINIMR_DNS_RR_TYPE_AAAA(sizeof(RR_AAAA_NAME)) RR_AAAA = {
    .type = MINIMR_DNS_TYPE_AAAA,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = generic_rr_handler,
    .name = RR_AAAA_NAME,
    // anything hereafter is not part of the basic struct minimr_dns_rr
    .ipv6 = RR_AAAA_IPv6
};

static MINIMR_DNS_RR_TYPE_PTR(sizeof(RR_PTR_NAME), sizeof(RR_PTR_DOMAIN)) RR_PTR = {
    .type = MINIMR_DNS_TYPE_PTR,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = generic_rr_handler,
    .name = RR_PTR_NAME,
    // anything hereafter is not part of the basic struct minimr_dns_rr
    .domain = RR_PTR_DOMAIN
};

static MINIMR_DNS_RR_TYPE_SRV(sizeof(RR_SRV_NAME), sizeof(RR_SRV_TARGET)) RR_SRV = {
    .type = MINIMR_DNS_TYPE_SRV,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = generic_rr_handler,
    .name = RR_PTR_NAME,
    // anything hereafter is not part of the basic struct minimr_dns_rr
    .priority = 1,
    .weight = 100,
    .port = 7,
    .target = RR_SRV_TARGET
};

static MINIMR_DNS_RR_TYPE_TXT(sizeof(RR_TXT_NAME), sizeof(RR_TXT_DATA)) RR_TXT = {
    .type = MINIMR_DNS_TYPE_TXT,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = generic_rr_handler,
    .name = RR_TXT_NAME,
    // anything hereafter is not part of the basic struct minimr_dns_rr
    .txt_length = sizeof(RR_TXT_DATA),
    .txt = RR_TXT_DATA
};

// isn't this much nicer?
static Custom_PTR_RR RR_CUSTOM = {
    .type = MINIMR_DNS_TYPE_PTR,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = custom_rr_handler,
    .name = RR_CUSTOM_PTR_NAME,
    // anything hereafter is not part of the basic struct minimr_dns_rr
    .domain_length = sizeof(RR_CUSTOM_PTR_NAME), // TODO automate for default case
    .domain = RR_CUSTOM_PTR_DOMAIN,
    .rr_a = (struct minimr_dns_rr *)&RR_A,
    .rr_aaaa = (struct minimr_dns_rr *)&RR_AAAA,
    .rr_txt = (struct minimr_dns_rr *)&RR_TXT,
};


// container for records handed to minimr
// can be static, dynamic, etc
static  struct minimr_dns_rr * records[] = {
    (struct minimr_dns_rr *)&RR_A,
    (struct minimr_dns_rr *)&RR_AAAA,
    (struct minimr_dns_rr *)&RR_PTR,
    (struct minimr_dns_rr *)&RR_SRV,
    (struct minimr_dns_rr *)&RR_TXT,
    NULL, // will be skipped (handy when you want to dynamically de-/activate records
    (struct minimr_dns_rr *)&RR_CUSTOM,
};

static uint16_t NRECORDS = sizeof(records) / sizeof(struct minimr_dns_rr *);

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
    MINIMR_ASSERT(type == minimr_dns_rr_fun_type_is_uptodate || type == minimr_dns_rr_fun_type_get_answer_rrs || type == minimr_dns_rr_fun_type_get_authority_rrs || type == minimr_dns_rr_fun_type_get_additional_rrs);


    if (type == minimr_dns_rr_fun_type_is_uptodate){
        return MINIMR_NOT_UPTODATE;
    }

    // it isn't necessarily safe to put this here

    va_list args;
    va_start(args, rr);

    uint8_t * outmsg = va_arg(args, uint8_t *);
    uint16_t * outmsglen = va_arg(args, uint16_t *);
    uint16_t outmsgmaxlen = va_arg(args, int); // uint16_t will be promoted to int
    uint16_t * nrr = va_arg(args, uint16_t *);

    va_end(args);


    if (type == minimr_dns_rr_fun_type_get_answer_rrs){

        if ((rr->type == MINIMR_DNS_TYPE_A && outmsgmaxlen < MINIMR_DNS_RR_A_SIZE(rr)) ||
            (rr->type == MINIMR_DNS_TYPE_AAAA && outmsgmaxlen < MINIMR_DNS_RR_AAAA_SIZE(rr)) ||
            (rr->type == MINIMR_DNS_TYPE_PTR && outmsgmaxlen < MINIMR_DNS_RR_PTR_SIZE(rr, *MINIMR_DNS_RR_PTR_GET_DOMAINLEN_PTR(rr))) ||
            (rr->type == MINIMR_DNS_TYPE_SRV && outmsgmaxlen < MINIMR_DNS_RR_SRV_SIZE(rr, *MINIMR_DNS_RR_SRV_GET_TARGETLEN_PTR(rr))) ||
            (rr->type == MINIMR_DNS_TYPE_TXT && outmsgmaxlen < MINIMR_DNS_RR_TXT_SIZE(rr, *MINIMR_DNS_RR_TXT_GET_TXTLEN_PTR(rr)))) {
            return MINIMR_NOT_OK;
        }

        uint16_t l = *outmsglen;

        // helper macros to write all the standard fields of the record
        // you can naturally do this manually and customize it ;)
        
        MINIMR_DNS_RR_WRITE(rr, outmsg, l)

        if (rr->type == MINIMR_DNS_TYPE_A) {
            MINIMR_DNS_RR_WRITE_A_BODY(rr, outmsg, l, MINIMR_DNS_RR_A_GET_IPv4_PTR(rr))
        }
        else if (rr->type == MINIMR_DNS_TYPE_AAAA) {
            MINIMR_DNS_RR_WRITE_AAAA_BODY(rr, outmsg, l, MINIMR_DNS_RR_AAAA_GET_IPv6_PTR(rr))
        }
        else if (rr->type == MINIMR_DNS_TYPE_PTR) {
            MINIMR_DNS_RR_WRITE_PTR_BODY(rr, outmsg, l, MINIMR_DNS_RR_PTR_GET_DOMAIN_PTR(rr), *MINIMR_DNS_RR_PTR_GET_DOMAINLEN_PTR(rr))
        }
        else if (rr->type == MINIMR_DNS_TYPE_SRV) {
            MINIMR_DNS_RR_WRITE_SRV_BODY(rr, outmsg, l, *MINIMR_DNS_RR_SRV_GET_PRIORITY_PTR(rr), *MINIMR_DNS_RR_SRV_GET_WEIGHT_PTR(rr), *MINIMR_DNS_RR_SRV_GET_PORT_PTR(rr), MINIMR_DNS_RR_SRV_GET_TARGET_PTR(rr), *MINIMR_DNS_RR_SRV_GET_TARGETLEN_PTR(rr))
        }
        else if (rr->type == MINIMR_DNS_TYPE_TXT) {
            MINIMR_DNS_RR_WRITE_TXT_BODY(rr, outmsg, l, MINIMR_DNS_RR_TXT_GET_TXT_PTR(rr), *MINIMR_DNS_RR_TXT_GET_TXTLEN_PTR(rr))
        }

        *outmsglen = l;
        *nrr = 1;

        MINIMR_DEBUGF("added %d RRs (totlen %d)\n", 1, l);

        return MINIMR_OK;
    }

    if (type == minimr_dns_rr_fun_type_get_authority_rrs){

        MINIMR_DEBUGF("no authority RRs to add\n");

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
                    (struct minimr_dns_rr *)&RR_TXT,
            };

            const static uint16_t nextrarr = sizeof(extrarrs) / sizeof(struct minimr_dns_rr *);

            uint16_t l = *outmsglen;

            for (int i = 0; i < nextrarr; i++){

                struct minimr_dns_rr * extra = extrarrs[i];


                if ((extra->type == MINIMR_DNS_TYPE_A && outmsgmaxlen < MINIMR_DNS_RR_A_SIZE(rr)) ||
                    (extra->type == MINIMR_DNS_TYPE_AAAA && outmsgmaxlen < MINIMR_DNS_RR_AAAA_SIZE(rr)) ||
                    (extra->type == MINIMR_DNS_TYPE_PTR && outmsgmaxlen < MINIMR_DNS_RR_PTR_SIZE(rr, *MINIMR_DNS_RR_PTR_GET_DOMAINLEN_PTR(rr))) ||
                    (extra->type == MINIMR_DNS_TYPE_SRV && outmsgmaxlen < MINIMR_DNS_RR_SRV_SIZE(rr, *MINIMR_DNS_RR_SRV_GET_TARGETLEN_PTR(rr))) ||
                    (extra->type == MINIMR_DNS_TYPE_TXT && outmsgmaxlen < MINIMR_DNS_RR_TXT_SIZE(rr, *MINIMR_DNS_RR_TXT_GET_TXTLEN_PTR(rr)))) {
                    return MINIMR_NOT_OK;
                }

                MINIMR_DNS_RR_WRITE(extra, outmsg, l)

                if (extra->type == MINIMR_DNS_TYPE_A) {
                    MINIMR_DNS_RR_WRITE_A_BODY(extra, outmsg, l, MINIMR_DNS_RR_A_GET_IPv4_PTR(extra))
                }
                else if (extra->type == MINIMR_DNS_TYPE_AAAA) {
                    MINIMR_DNS_RR_WRITE_AAAA_BODY(extra, outmsg, l, MINIMR_DNS_RR_AAAA_GET_IPv6_PTR(extra))
                }
                else if (extra->type == MINIMR_DNS_TYPE_PTR) {
                    MINIMR_DNS_RR_WRITE_PTR_BODY(extra, outmsg, l, MINIMR_DNS_RR_PTR_GET_DOMAIN_PTR(extra), *MINIMR_DNS_RR_PTR_GET_DOMAINLEN_PTR(extra))
                }
                else if (extra->type == MINIMR_DNS_TYPE_SRV) {
                    MINIMR_DNS_RR_WRITE_SRV_BODY(extra, outmsg, l, *MINIMR_DNS_RR_SRV_GET_PRIORITY_PTR(extra), *MINIMR_DNS_RR_SRV_GET_WEIGHT_PTR(extra), *MINIMR_DNS_RR_SRV_GET_PORT_PTR(extra), MINIMR_DNS_RR_SRV_GET_TARGET_PTR(extra), *MINIMR_DNS_RR_SRV_GET_TARGETLEN_PTR(extra))
                }
                else if (extra->type == MINIMR_DNS_TYPE_TXT) {
                    MINIMR_DNS_RR_WRITE_TXT_BODY(extra, outmsg, l, MINIMR_DNS_RR_TXT_GET_TXT_PTR(extra), *MINIMR_DNS_RR_TXT_GET_TXTLEN_PTR(extra))
                }

                *nrr += 1;
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
    MINIMR_ASSERT(type == minimr_dns_rr_fun_type_is_uptodate || type == minimr_dns_rr_fun_type_get_answer_rrs || type == minimr_dns_rr_fun_type_get_authority_rrs || type == minimr_dns_rr_fun_type_get_additional_rrs);

    // as this handler has only been assigned to our custom RR this MUST be true
    MINIMR_ASSERT( rr == (struct minimr_dns_rr *)&RR_CUSTOM );

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
    uint16_t outmsgmaxlen = va_arg(args, int); // uint16_t will be promoted to int
    uint16_t * nrr = va_arg(args, uint16_t *);

    va_end(args);


    uint16_t l = *outmsglen;

    if (type == minimr_dns_rr_fun_type_get_answer_rrs){

        if (outmsgmaxlen < MINIMR_DNS_RR_A_SIZE(rr)){
            return MINIMR_NOT_OK;
        }


        // shorthand for:
        // MINIMR_DNS_RR_WRITE(rr, outmsg, l)
        // MINIMR_DNS_RR_WRITE_PTR_BODY(rr, outmsg, l, MINIMR_DNS_RR_A_GET_IPv4_PTR(rr))

        MINIMR_DNS_RR_WRITE_PTR(rr, outmsg, l, custom_rr->domain, custom_rr->domain_length)

        MINIMR_DEBUGF("added %d RRs (totlen %d)\n", 1, l);

        return MINIMR_OK;
    }


    if (type == minimr_dns_rr_fun_type_get_additional_rrs) {

        if (outmsgmaxlen < MINIMR_DNS_RR_A_SIZE(custom_rr->rr_a) + MINIMR_DNS_RR_AAAA_SIZE(custom_rr->rr_aaaa) + MINIMR_DNS_RR_TXT_SIZE(custom_rr->rr_txt, *MINIMR_DNS_RR_TXT_GET_TXTLEN_PTR(custom_rr->rr_txt))){
            return MINIMR_NOT_OK;
        }

        MINIMR_DNS_RR_WRITE_A(custom_rr->rr_a, outmsg, l, MINIMR_DNS_RR_A_GET_IPv4_PTR(custom_rr->rr_a))

        MINIMR_DNS_RR_WRITE_AAAA(custom_rr->rr_a, outmsg, l, MINIMR_DNS_RR_A_GET_IPv4_PTR(custom_rr->rr_a))

        MINIMR_DNS_RR_WRITE_TXT(custom_rr->rr_txt, outmsg, l, MINIMR_DNS_RR_TXT_GET_TXT_PTR(custom_rr->rr_txt), *MINIMR_DNS_RR_TXT_GET_TXTLEN_PTR(custom_rr->rr_txt))

        *nrr += 3;

    }

    *outmsglen = l;

    return MINIMR_OK;
}

/* other functions */

uint16_t receive_udp_packet(uint8_t * payload, uint16_t maxlen){

    MINIMR_ASSERT(payload != NULL);
    MINIMR_ASSERT(maxlen > 0);

    size_t r = fread(payload, sizeof(uint8_t), maxlen, stdin);

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

        if (records[i] == NULL){
            continue;
        }

        minimr_dns_normalize_name(records[i]->name, &records[i]->name_length);

        if (records[i]->type == MINIMR_DNS_TYPE_TXT){
            // NOTE: MINIMR_DNS_RR_TXT_GET_PTR makes assumptions about memory layout (when using predefined type)
            minimr_dns_normalize_txt(MINIMR_DNS_RR_TXT_GET_TXT_PTR(records[i]), MINIMR_DNS_RR_TXT_GET_TXTLEN_PTR(records[i]), MY_TXT_MARKER);
        }
        if (records[i]->type == MINIMR_DNS_TYPE_SRV){
            minimr_dns_normalize_name(MINIMR_DNS_RR_SRV_GET_TARGET_PTR(records[i]), MINIMR_DNS_RR_SRV_GET_TARGETLEN_PTR(records[i]));
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

        uint8_t unicast_requested;

        uint8_t res = minimr_handle_msg(in, inlen, qstats, NQSTATS, records, NRECORDS, out, &outlen, sizeof(out), &unicast_requested);

        if (res == MINIMR_IGNORE){
            // it's not a message we should bother about
            MINIMR_DEBUGF("MINIMR_IGNORE\n");
            continue;
        }

        if (res == MINIMR_DNS_HDR2_RCODE_FORMERR){
            // we could send a response to the querying device with this result code
            // don't do this if it was a multicast
            MINIMR_DEBUGF("MINIMR_DNS_HDR2_RCODE_FORMERR\n");
            continue;
        }

        if (res == MINIMR_DNS_HDR2_RCODE_SERVAIL){
            // we could send a response to the querying device with this result code
            // don't do this if it was a multicast
            MINIMR_DEBUGF("MINIMR_DNS_HDR2_RCODE_SERVAIL\n");
            continue;
        }

        if (res != MINIMR_DNS_HDR2_RCODE_NOERROR){
            // just a last test for safety
            MINIMR_DEBUGF("other error!\n");
            continue;
        }

        MINIMR_DEBUGF("MINIMR_DNS_HDR2_RCODE_NOERROR\n");

        send_udp_packet(out, outlen);

    }


    return 0;
}