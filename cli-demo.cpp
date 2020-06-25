#include "minimr.h"

#include <iostream>


using namespace std;

/* basic config */

#define NQSTATS 10


/* function signatures */

int fun_a(enum minimr_dns_rr_fun_type fun, ...);
int fun_aaaa(enum minimr_dns_rr_fun_type fun, ...);
int fun_ptr(enum minimr_dns_rr_fun_type fun, ...);
int fun_srv(enum minimr_dns_rr_fun_type fun, ...);
int fun_txt(enum minimr_dns_rr_fun_type fun, ...);

/* RR config */

#define RR_A_NAME "Where be Kittens.local"
//#define RR_AAAA_NAME "asdfasdf.local"

#define RR_PTR_NAME "_echo._udp.local"
#define RR_PTR_DOMAIN RR_A_NAME

#define RR_SRV_NAME "Here be Echoing Kittens._echo._udp.local"
#define RR_SRV_TARGET RR_A_NAME

#define RR_TXT_NAME RR_A_NAME
#define RR_TXT_DATA "--key1=value1--key2=value2--key3=value3"


MINIMR_DNS_RR_TYPE_A(sizeof(RR_A_NAME)) RR_A = {
    .type = MINIMR_DNS_TYPE_A,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .name_length = sizeof(RR_A_NAME) - 1,
    .fun = fun_a,
    .name = RR_A_NAME
};

//MINIMR_DNS_RR_TYPE_AAAA(sizeof(RR_AAAA_NAME)) RR_AAAA = {
//    .type = MINIMR_DNS_TYPE_AAAA,
//    .cache_class = MINIMR_DNS_CLASS_IN,
//    .ttl = 60,
//    .name_length = sizeof(RR_AAAA_NAME) - 1,
//    .fun = fun_aaaa,
//    .name = RR_AAAA_NAME
//};

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
        .fun = fun_ptr,
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
        .fun = fun_ptr,
        .name = RR_TXT_NAME,
        .txt = RR_TXT_DATA
};


// being naughty here
struct minimr_dns_rr * records[] = {
    (struct minimr_dns_rr *)&RR_A,
    (struct minimr_dns_rr *)&RR_PTR,
    (struct minimr_dns_rr *)&RR_SRV,
    (struct minimr_dns_rr *)&RR_TXT,
};

const uint16_t nrecords = sizeof(records) / sizeof(struct minimr_dns_rr *);


int fun_a(enum minimr_dns_rr_fun_type fun, ...){
    return 0;
}

int fun_aaaa(enum minimr_dns_rr_fun_type fun, ...){
    return 0;
}

int fun_ptr(enum minimr_dns_rr_fun_type fun, ...){
    return 0;
}

int fun_srv(enum minimr_dns_rr_fun_type fun, ...){
    return 0;
}

int fun_txt(enum minimr_dns_rr_fun_type fun, ...){
    return 0;
}

int main() {

    for (int i = 0; i < nrecords; i++){
        minimr_dns_normalize_name(records[i]);

        if (records[i]->type){
            // NOTE: MINIMR_DNS_RR_GET_TXT_FIELD makes assumptions about memory layout
            minimr_dns_normalize_txt(MINIMR_DNS_RR_GET_TXT_FIELD(records[i]));
        }
    }

    struct minimr_dns_query_stat qstats[NQSTATS];


    while(1){

    }


    return 0;
}