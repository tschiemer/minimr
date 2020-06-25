#include "minimr.h"

#include <iostream>
#include <unistd.h>
#include <cassert>


using namespace std;

/***** basic config *****/

#define NQSTATS 10

/***** types *****/


/***** function signatures *****/

// note, you could also use the same callback function for all RRs (that's why it also get the rr ptr ;)

int fun_a(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...);
int fun_aaaa(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...);
int fun_ptr(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...);
int fun_srv(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...);
int fun_txt(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...);
int fun_custom(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...);


// dummy functions
uint16_t receive_udp_packet(uint8_t * payload, uint16_t maxlen);
void send_udp_packet(uint8_t * payload, uint16_t len);

/***** local variables *****/

/* RR config */

#define RR_A_NAME "Where be Kittens.local"
#define RR_A_IPv4 {127, 0, 0, 1}

#define RR_AAAA_NAME "asdfasdf.local"
#define RR_AAAA_IPv6 {1,2,3,4,5,6,7,8}

#define RR_PTR_NAME "_echo._udp.local"
#define RR_PTR_DOMAIN RR_A_NAME

#define RR_SRV_NAME "Here be Echoing Kittens._echo._udp.local"
#define RR_SRV_TARGET RR_A_NAME

#define RR_TXT_NAME RR_A_NAME
#define RR_TXT_DATA "--key1=value1--key2=value2--key3=value3"

#define RR_CUSTOM_NAME "here be dragons.local"

MINIMR_DNS_RR_TYPE_A(sizeof(RR_A_NAME)) RR_A = {
    .type = MINIMR_DNS_TYPE_A,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .name_length = sizeof(RR_A_NAME) - 1,
    .fun = fun_a,
    .name = RR_A_NAME,
    .ipv4 = RR_A_IPv4
};

MINIMR_DNS_RR_TYPE_AAAA(sizeof(RR_AAAA_NAME)) RR_AAAA = {
    .type = MINIMR_DNS_TYPE_AAAA,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .name_length = sizeof(RR_AAAA_NAME) - 1,
    .fun = fun_aaaa,
    .name = RR_AAAA_NAME,
    .ipv6 = RR_AAAA_IPv6
};

MINIMR_DNS_RR_TYPE_PTR(sizeof(RR_PTR_NAME), sizeof(RR_PTR_DOMAIN)) RR_PTR = {
    .type = MINIMR_DNS_TYPE_PTR,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .name_length = sizeof(RR_PTR_NAME) - 1,
    .fun = fun_ptr,
    .name = RR_PTR_NAME,
    .domain = RR_PTR_DOMAIN
};

MINIMR_DNS_RR_TYPE_SRV(sizeof(RR_SRV_NAME), sizeof(RR_SRV_TARGET)) RR_SRV = {
        .type = MINIMR_DNS_TYPE_SRV,
        .cache_class = MINIMR_DNS_CLASS_IN,
        .ttl = 60,
        .name_length = sizeof(RR_PTR_NAME) - 1,
        .fun = fun_srv,
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
        .name_length = sizeof(RR_TXT_NAME) - 1,
        .fun = fun_txt,
        .name = RR_TXT_NAME,
        .txt = RR_TXT_DATA
};

MINIMR_DNS_RR_TYPE_BEGIN(sizeof(RR_CUSTOM_NAME))
    // does not have any additional datastructures
    // you could use this to NOT store any data, but compute it every time when needed ;)
MINIMR_DNS_RR_TYPE_END() RR_CUSTOM = {
        .type = MINIMR_DNS_TYPE_A,
        .cache_class = MINIMR_DNS_CLASS_IN,
        .ttl = 60,
        .name_length = sizeof(RR_TXT_NAME) - 1,
        .fun = fun_custom
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

/* rr callbacks */

int fun_a(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...){
    return 0;
}

int fun_aaaa(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...){
    return 0;
}

int fun_ptr(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...){
    return 0;
}

int fun_srv(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...){
    return 0;
}

int fun_txt(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...){
    return 0;
}

int fun_custom(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...){
    return 0;
}

/* other functions */

uint16_t receive_udp_packet(uint8_t * payload, uint16_t maxlen){

    assert(payload != NULL);
    assert(maxlen > 0);

    size_t r = read(STDIN_FILENO, payload, maxlen);

    printf("read %lu bytes\n", r);
    fflush(stdout);

    return r;
}

void send_udp_packet(uint8_t * payload, uint16_t len){
    write(STDOUT_FILENO, payload, len);
}

int main() {



    for (int i = 0; i < NRECORDS; i++){
        minimr_dns_normalize_name(records[i]);

        if (records[i]->type){
            // NOTE: MINIMR_DNS_RR_GET_TXT_FIELD makes assumptions about memory layout (when using predefined type)
            minimr_dns_normalize_txt(MINIMR_DNS_RR_GET_TXT_FIELD(records[i]));
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
            continue;
        }

        if (res == MINIMR_DNS_HDR2_RCODE_FORMERR){
            // we could send a response to the querying device with this result code
            // don't do this if it was a multicast
            continue;
        }

        if (res == MINIMR_DNS_HDR2_RCODE_SERVAIL){
            // we could send a response to the querying device with this result code
            // don't do this if it was a multicast
            continue;
        }

        if (res != MINIMR_DNS_HDR2_RCODE_NOERROR){
            // just a last test for safety
            continue;
        }

        send_udp_packet(out, outlen);


    }


    return 0;
}