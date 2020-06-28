#include "../minimr.h"

#include <iostream>
#include <unistd.h>
#include <cassert>
#include <stdarg.h>
#include <chrono>
#include <thread>

using namespace std;


/***** basic config *****/

// Our records are unique and we do not require probing
#define RECORDS_ARE_UNIQUE 0

// should be a value between 2 - 8
#define NUMBER_OF_ANNOUNCEMENTS 2

// limits the number of questions we can actually answer
// likely this can be identical to your number of RRs
#define NQSTATS 10

// note: actual names parts MUST be preceeded by a dot character ('.') - at least when you make use of the  minimr_dns_normalize_name() function as below
// otherwise you can encode the length of each following component, such as "\x0fWhere be Kittens\x05local"
// also, the terminating NUL-character '\0' is necessary.

#define HOST_NAME ".where-be-kittens.local"
#define SERVICE_NAME ".Here be Echoing Kittens._echo._udp.local"
#define SERVICE_PTR_NAME "._echo._udp.local"
#define CUSTOM_PTR_NAME "._echo._tcp.local"

// the predefined IPv4 type is an uint8_t[4]
#define HOST_IPv4 {127, 0, 0, 1}
// the predefined IPv6 type is an uint16_t[8]
#define HOST_IPv6 {1,2,3,4,5,6,7,8}

// when using minimr_dns_normalize_field() all key/value pairs must be preceeded by one character to be defined by you
// MUST NOT be the NUL character '\0' which is used to detect the end of the data
#define MY_TXT_MARKER '.'
#define SERVICE_DATA ".key1=value1.key2=value2.key3=value3"





/***** types *****/

typedef enum { Unicast, Multicast } UnicastMulticast;
typedef void * my_socket_or_ipaddr_type;

typedef MINIMR_DNS_RR_TYPE_A(sizeof(HOST_NAME)) RR_A_t;
typedef MINIMR_DNS_RR_TYPE_AAAA(sizeof(HOST_NAME)) RR_AAAA_t;
typedef MINIMR_DNS_RR_TYPE_PTR(sizeof(SERVICE_NAME), sizeof(HOST_NAME)) RR_PTR_t;
typedef MINIMR_DNS_RR_TYPE_TXT(sizeof(SERVICE_NAME), sizeof(SERVICE_DATA)) RR_TXT_t;
typedef MINIMR_DNS_RR_TYPE_SRV(sizeof(SERVICE_NAME), sizeof(HOST_NAME)) RR_SRV_t;

typedef
MINIMR_DNS_RR_TYPE_BEGIN(sizeof(CUSTOM_PTR_NAME))
MINIMR_DNS_RR_TYPE_BODY_PTR(sizeof(HOST_NAME))
    RR_A_t * rr_a;
    RR_AAAA_t * rr_aaaa;
    RR_TXT_t * rr_txt;
MINIMR_DNS_RR_TYPE_END()
Custom_PTR_RR;

typedef enum {
    State_Init,
    State_ProbingQuery,
    State_ProbingAwaitAnswers,
    State_ProbingLostTie,
    State_Reconfigure,
    State_Announce,
    State_Responding
} State;

/***** function signatures *****/

#if MINIMR_TIMESTAMP_USE
uint32_t my_timestamp_now();
#endif

// rr handler functions
static int generic_rr_handler(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...);
static int custom_rr_handler(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...);


// dummy functions
static uint16_t receive_udp_packet(uint8_t * payload, uint16_t maxlen, my_socket_or_ipaddr_type from_addr);
static void send_udp_packet(uint8_t * payload, uint16_t len, UnicastMulticast um, ...);

/***** local variables *****/

/* RR config */


static RR_A_t RR_A = {
    .type = MINIMR_DNS_TYPE_A,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 0xffffffff,
    .fun = generic_rr_handler,
    .name = HOST_NAME,
    // anything hereafter is not part of the basic struct minimr_dns_rr
    .ipv4 = HOST_IPv4
};

static RR_AAAA_t RR_AAAA = {
    .type = MINIMR_DNS_TYPE_AAAA,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = generic_rr_handler,
    .name = HOST_NAME,
    // anything hereafter is not part of the basic struct minimr_dns_rr
    .ipv6 = HOST_IPv6
};

static RR_PTR_t RR_PTR = {
    .type = MINIMR_DNS_TYPE_PTR,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = generic_rr_handler,
    .name = SERVICE_NAME,
    // anything hereafter is not part of the basic struct minimr_dns_rr
    .domain = HOST_NAME
};


static RR_TXT_t RR_TXT = {
        .type = MINIMR_DNS_TYPE_TXT,
        .cache_class = MINIMR_DNS_CLASS_IN,
        .ttl = 60,
        .fun = generic_rr_handler,
        .name = SERVICE_NAME,
        // anything hereafter is not part of the basic struct minimr_dns_rr
        .txt_length = sizeof(SERVICE_DATA),
        .txt = SERVICE_DATA
};

static RR_SRV_t RR_SRV = {
    .type = MINIMR_DNS_TYPE_SRV,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = generic_rr_handler,
    .name = SERVICE_NAME,
    // anything hereafter is not part of the basic struct minimr_dns_rr
    .priority = 1,
    .weight = 100,
    .port = 7,
    .target = HOST_NAME
};


// isn't this much nicer?
static Custom_PTR_RR RR_PTR_CUSTOM = {
    .type = MINIMR_DNS_TYPE_PTR,
    .cache_class = MINIMR_DNS_CLASS_IN,
    .ttl = 60,
    .fun = custom_rr_handler,
    .name = CUSTOM_PTR_NAME,
    // anything hereafter is not part of the basic struct minimr_dns_rr
    .domain = HOST_NAME,
    .rr_a = &RR_A,
    .rr_aaaa = &RR_AAAA,
    .rr_txt = &RR_TXT,
};


// container for records handed to minimr
// can be static, dynamic, etc
static  struct minimr_dns_rr * records[] = {
    (struct minimr_dns_rr *)&RR_A,
    (struct minimr_dns_rr *)&RR_AAAA,
    (struct minimr_dns_rr *)&RR_TXT, // TXT before SRV
    (struct minimr_dns_rr *)&RR_SRV,
    (struct minimr_dns_rr *)&RR_PTR, // PTRs last
    NULL, // will be skipped (handy when you want to dynamically de-/activate records
    (struct minimr_dns_rr *)&RR_PTR_CUSTOM,
};

static uint16_t NRECORDS = sizeof(records) / sizeof(struct minimr_dns_rr *);

/***** functions *****/

uint32_t my_timestamp_now_ms()
{
    //https://stackoverflow.com/questions/31255486/c-how-do-i-convert-a-stdchronotime-point-to-long-and-back

    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
    return now_ms.time_since_epoch().count();
}

/** RR callbacks
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_is_uptodate, struct minimr_dns_rr * rr, struct minimr_dns_rr_stat * rstat, uint8_t * msg );
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_get_rr, struct minimr_dns_rr * rr, uint8_t * outmsg, uint16_t * outlen, uint16_t outmsgmaxlen, uint16_t * nrr)
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_get_authority_rrs, .. ) // same as above
 * minimr_dns_rr_fun( minimr_dns_rr_fun_type_get_extra_rrs, .. ) // same as above
 * */

// handlers are only called for RRs that are a direct match
// thus a handler also knows best when to add additional
int generic_rr_handler(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...)
{
    MINIMR_ASSERT(MINIMR_DNS_RR_FUN_TYPE_IS_VALID(type));


    if (type == minimr_dns_rr_fun_type_respond_to){

        // TODO check if is up-to-date, wrong or whatever?

        #if MINIMR_TIMESTAMP_USE
        uint32_t now = my_timestamp_now_ms();

        // if already answered within the last second, then don't answer
        if (rr->last_responded + 1000 < now){
            return MINIMR_DO_NOT_RESPOND;
        }
        #endif

        return MINIMR_RESPOND;
    }

    // it isn't necessarily safe to put this here

    va_list args;
    va_start(args, rr);

    uint8_t * outmsg = va_arg(args, uint8_t *);
    uint16_t * outmsglen = va_arg(args, uint16_t *);
    uint16_t outmsgmaxlen = va_arg(args, int); // uint16_t will be promoted to int
    uint16_t * nrr = va_arg(args, uint16_t *);

    uint8_t unicast_requested = 0;
    if (type == minimr_dns_rr_fun_type_get_query){
        unicast_requested = va_arg(args,int); // uint8_t will be promoted to int
    }

    va_end(args);


    if (type == minimr_dns_rr_fun_type_get_rr){

        if ((rr->type == MINIMR_DNS_TYPE_A && outmsgmaxlen < MINIMR_DNS_RR_A_SIZE(rr->name_length)) ||
            (rr->type == MINIMR_DNS_TYPE_AAAA && outmsgmaxlen < MINIMR_DNS_RR_AAAA_SIZE(rr->name_length)) ||
            (rr->type == MINIMR_DNS_TYPE_PTR && outmsgmaxlen < MINIMR_DNS_RR_PTR_SIZE(rr->name_length, ((RR_PTR_t*)rr)->domain_length)) ||
            (rr->type == MINIMR_DNS_TYPE_SRV && outmsgmaxlen < MINIMR_DNS_RR_SRV_SIZE(rr->name_length, ((RR_SRV_t*)rr)->target_length)) ||
            (rr->type == MINIMR_DNS_TYPE_TXT && outmsgmaxlen < MINIMR_DNS_RR_TXT_SIZE(rr->name_length, ((RR_TXT_t*)rr)->txt_length))) {
            return MINIMR_NOT_OK;
        }

        uint16_t l = *outmsglen;

        // helper macros to write all the standard fields of the record
        // you can naturally do this manually and customize it ;)

        MINIMR_DNS_RR_WRITE_COMMON(outmsg, l, rr->name, rr->name_length, rr->type, rr->cache_class, rr->ttl);

        if (rr->type == MINIMR_DNS_TYPE_A) {
            MINIMR_DNS_RR_WRITE_A_BODY(outmsg, l, ((RR_A_t*)rr)->ipv4);
        }
        else if (rr->type == MINIMR_DNS_TYPE_AAAA) {
            MINIMR_DNS_RR_WRITE_A_BODY(outmsg, l, ((RR_AAAA_t*)rr)->ipv6);
        }
        else if (rr->type == MINIMR_DNS_TYPE_PTR) {
            MINIMR_DNS_RR_WRITE_PTR_BODY(outmsg, l, ((RR_PTR_t*)rr)->domain, ((RR_PTR_t*)rr)->domain_length);
        }
        else if (rr->type == MINIMR_DNS_TYPE_SRV) {
            MINIMR_DNS_RR_WRITE_SRV_BODY(outmsg, l, ((RR_SRV_t*)rr)->priority, ((RR_SRV_t*)rr)->weight, ((RR_SRV_t*)rr)->port, ((RR_SRV_t*)rr)->target, ((RR_SRV_t*)rr)->target_length);
        }
        else if (rr->type == MINIMR_DNS_TYPE_TXT) {
            MINIMR_DNS_RR_WRITE_TXT_BODY(outmsg, l, ((RR_TXT_t*)rr)->txt, ((RR_TXT_t*)rr)->txt_length);
        }

        *outmsglen = l;
        if (nrr != NULL){
            *nrr = 1;
        }

        MINIMR_DEBUGF("added %d RRs (totlen %d)\n", 1, l);

        return MINIMR_OK;
    }

    if (type == minimr_dns_rr_fun_type_get_authority_rrs){

        MINIMR_DEBUGF("no authority RRs to add\n");

        return MINIMR_OK;
    }

    if (type == minimr_dns_rr_fun_type_get_extra_rrs){

        //
        if (rr->type == MINIMR_DNS_TYPE_PTR){

            // this only works because we the actual records are referencable
            if (generic_rr_handler(minimr_dns_rr_fun_type_get_rr, (struct minimr_dns_rr *)&RR_A, outmsg, outmsglen, outmsgmaxlen, NULL) != MINIMR_OK) return MINIMR_NOT_OK;
            if (generic_rr_handler(minimr_dns_rr_fun_type_get_rr, (struct minimr_dns_rr *)&RR_AAAA, outmsg, outmsglen, outmsgmaxlen, NULL) != MINIMR_OK) return MINIMR_NOT_OK;
            if (generic_rr_handler(minimr_dns_rr_fun_type_get_rr, (struct minimr_dns_rr *)&RR_SRV, outmsg, outmsglen, outmsgmaxlen, NULL) != MINIMR_OK) return MINIMR_NOT_OK;
            if (generic_rr_handler(minimr_dns_rr_fun_type_get_rr, (struct minimr_dns_rr *)&RR_TXT, outmsg, outmsglen, outmsgmaxlen, NULL) != MINIMR_OK) return MINIMR_NOT_OK;

            if (nrr != NULL){
                *nrr = 4;
            }
        }

        return MINIMR_OK;
    }

    if (type == minimr_dns_rr_fun_type_get_query){

        // only add queries for these types
        if (rr->type != MINIMR_DNS_TYPE_A && rr->type != MINIMR_DNS_TYPE_AAAA && rr->type != MINIMR_DNS_TYPE_SRV){
            return MINIMR_OK;
        }

        if (outmsgmaxlen < MINIMR_DNS_Q_SIZE(rr->name_length)){
            return MINIMR_NOT_OK;
        }

        uint16_t l = *outmsglen;

        // queries always look the same, independent of type
        MINIMR_DNS_Q_WRITE(outmsg, l, rr->name, rr->name_length, rr->type, rr->cache_class, unicast_requested);
        if (nrr != NULL){
            *nrr += 1;
        }

        *outmsglen = l;

        return MINIMR_OK;
    }

    return MINIMR_OK;
}

int custom_rr_handler(enum minimr_dns_rr_fun_type type, struct minimr_dns_rr * rr, ...)
{
    MINIMR_ASSERT(type == minimr_dns_rr_fun_type_respond_to || type == minimr_dns_rr_fun_type_get_rr || type == minimr_dns_rr_fun_type_get_authority_rrs || type == minimr_dns_rr_fun_type_get_extra_rrs);

    // as this handler has only been assigned to our custom RR this MUST be true
    MINIMR_ASSERT( rr == (struct minimr_dns_rr *)&RR_PTR_CUSTOM );

    Custom_PTR_RR * custom_rr = (Custom_PTR_RR*)rr;

    if (type == minimr_dns_rr_fun_type_respond_to){

        // TODO check if is up-to-date, wrong or whatever?

        #if MINIMR_TIMESTAMP_USE
        uint32_t now = my_timestamp_now_ms();

        // if already answered within the last second, then don't answer
        if (rr->last_responded + 1000 < now){
            return MINIMR_DO_NOT_RESPOND;
        }
        #endif

        return MINIMR_RESPOND;
    }


    // now this is a proper guard (but should not be needed if we assume the best)
    if (type != minimr_dns_rr_fun_type_get_rr && type != minimr_dns_rr_fun_type_get_authority_rrs && type != minimr_dns_rr_fun_type_get_extra_rrs){
        return MINIMR_NOT_OK;
    }

    va_list args;
    va_start(args, rr);

    uint8_t * outmsg = va_arg(args, uint8_t *);
    uint16_t * outmsglen = va_arg(args, uint16_t *);
    uint16_t outmsgmaxlen = va_arg(args, int); // uint16_t will be promoted to int
    uint16_t * nrr = va_arg(args, uint16_t *);

    uint8_t unicast_requested = 0;
    if (type == minimr_dns_rr_fun_type_get_query){
        unicast_requested = va_arg(args,int); // uint8_t will be promoted to int
    }

    va_end(args);


    uint16_t l = *outmsglen;

    if (type == minimr_dns_rr_fun_type_get_rr){

        if (outmsgmaxlen < MINIMR_DNS_RR_A_SIZE(rr->name_length)){
            return MINIMR_NOT_OK;
        }


        // shorthand for:
        // MINIMR_DNS_RR_WRITE(rr, outmsg, l)
        // MINIMR_DNS_RR_WRITE_PTR_BODY(rr, outmsg, l, MINIMR_DNS_RR_A_GET_IPv4_PTR(rr))

        MINIMR_DNS_RR_WRITE_PTR(outmsg, l, rr->name, rr->name_length, rr->type, rr->cache_class, rr->ttl, custom_rr->domain, custom_rr->domain_length)

        MINIMR_DEBUGF("added %d RRs (totlen %d)\n", 1, l);

        if (nrr != NULL){
            *nrr = 1;
        }

        return MINIMR_OK;
    }


    if (type == minimr_dns_rr_fun_type_get_extra_rrs) {

        // this only works because we the actual records are referencable
        if (custom_rr->rr_a->fun(minimr_dns_rr_fun_type_get_rr, (struct minimr_dns_rr *)custom_rr->rr_a, outmsg, outmsglen, outmsgmaxlen, NULL) != MINIMR_OK) return MINIMR_NOT_OK;
        if (custom_rr->rr_a->fun(minimr_dns_rr_fun_type_get_rr, (struct minimr_dns_rr *)custom_rr->rr_aaaa, outmsg, outmsglen, outmsgmaxlen, NULL) != MINIMR_OK) return MINIMR_NOT_OK;
        if (custom_rr->rr_a->fun(minimr_dns_rr_fun_type_get_rr, (struct minimr_dns_rr *)custom_rr->rr_txt, outmsg, outmsglen, outmsgmaxlen, NULL) != MINIMR_OK) return MINIMR_NOT_OK;

        if (nrr != NULL){
            *nrr = 3;
        }

    }

    if (type == minimr_dns_rr_fun_type_get_query){

        MINIMR_DEBUGF("This is a ptr record - if we ask about it we will definitely get answers as long there are any services (so never query a PTR record during initial probing)\n");

    }

    *outmsglen = l;

    return MINIMR_OK;
}

/* other functions */


uint16_t receive_udp_packet(uint8_t * payload, uint16_t maxlen, my_socket_or_ipaddr_type from_addr)
{

    MINIMR_ASSERT(payload != NULL);
    MINIMR_ASSERT(maxlen > 0);

    // from_addr is not really used

    size_t r = fread(payload, sizeof(uint8_t), maxlen, stdin);

    return r;
}

void send_udp_packet(uint8_t * payload, uint16_t len, UnicastMulticast um, ...)
{

    if (len == 0){
        return;
    }

    static volatile bool mutex = false;

    while(mutex){
        this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    mutex = true;

    // we pretty much ignore the unicast (and to_addr) option - it's intended to make its use clear

    fwrite(payload, sizeof(uint8_t), len, stdout);
    fflush(stdout);

    mutex = false;
}

int main()
{

    // properly initialize records
    for (int i = 0; i < NRECORDS; i++){

        if (records[i] == NULL){
            continue;
        }

        minimr_dns_normalize_name(records[i]->name, &records[i]->name_length);

        if (records[i]->type == MINIMR_DNS_TYPE_TXT){
            // NOTE: MINIMR_DNS_RR_TXT_GET_PTR makes assumptions about memory layout (when using predefined type)
            minimr_dns_normalize_txt(((RR_TXT_t*)records[i])->txt, &((RR_TXT_t*)records[i])->txt_length, MY_TXT_MARKER);
        }
        if (records[i]->type == MINIMR_DNS_TYPE_SRV){
            minimr_dns_normalize_name(((RR_SRV_t*)records[i])->target, &((RR_SRV_t*)records[i])->target_length);
        }
    }


    struct minimr_dns_query_stat qstats[NQSTATS];

    static volatile State state = State_Init;

    uint8_t nprobe = 0;

    my_socket_or_ipaddr_type from_addr;

    uint8_t in[2048];
    uint16_t inlen = 0;
    uint8_t out[2048];
    uint16_t outlen = 0;

    while(!feof(stdin)){

        if (state == State_Init){
            // well whatever
            #if RECORDS_ARE_UNIQUE
            state = State_Announce;
            #else
            state = State_ProbingQuery;
            #endif
        }



        #if RECORDS_ARE_UNIQUE == 0
        if (state == State_ProbingQuery){

            outlen = MINIMR_DNS_HDR_SIZE;

            uint16_t nq = 3;
            uint16_t nrr_wishlist = 0;

            MINIMR_DNS_HDR_WRITE_PROBEQUERY(out, nq, nrr_wishlist);
//
            uint8_t unicast_requested = 1;

            // our questions (only one of A/AAAA and service related records TXT/SRV needed, using ANY qtype)
            MINIMR_DNS_Q_WRITE(out, outlen, RR_A.name, RR_A.name_length, MINIMR_DNS_TYPE_ANY, MINIMR_DNS_CLASS_IN, unicast_requested);
            MINIMR_DNS_Q_WRITE(out, outlen, RR_SRV.name, RR_SRV.name_length, MINIMR_DNS_TYPE_ANY, MINIMR_DNS_CLASS_IN, unicast_requested);

            // our record wishlist which will be added to the authrr section

            // different ways of writing a record
            RR_A.fun(minimr_dns_rr_fun_type_get_rr, (struct minimr_dns_rr*)&RR_A, out, outlen, sizeof(out), NULL);
            RR_AAAA.fun(minimr_dns_rr_fun_type_get_rr, (struct minimr_dns_rr*)&RR_AAAA, out, outlen, sizeof(out), NULL);
            generic_rr_handler(minimr_dns_rr_fun_type_get_rr, (struct minimr_dns_rr*)&RR_TXT, out, outlen, sizeof(out), NULL);
            MINIMR_DNS_RR_WRITE_SRV(out, outlen, RR_SRV.name, RR_SRV.name_length, RR_SRV.type, RR_SRV.cache_class, RR_SRV.ttl, RR_SRV.priority, RR_SRV.weight, RR_SRV.port, RR_SRV.target, RR_SRV.target_length);

            // if is first probe wait random time between 0 - 250 ms
            if (nprobe == 0){
                std::this_thread::sleep_for(std::chrono::milliseconds((rand() % MINIMR_DNS_PROBE_BOOTUP_DELAY_MSEC)));
            }

            nprobe++;

            state = State_ProbingAwaitAnswers;

            std::thread([&nprobe](){
                std::this_thread::sleep_for(std::chrono::milliseconds(MINIMR_DNS_PROBE_WAIT_MSEC));

                if (state != State_ProbingAwaitAnswers){
                    return;
                }

                if (nprobe < 3){
                    state = State_ProbingQuery;
                } else {
                    state = State_Announce;
                }
            });

            send_udp_packet(out, outlen, Multicast, from_addr);

            continue;
        }

        if (state == State_ProbingAwaitAnswers){

            // we're hoping (not) to be receiving messages
            inlen = receive_udp_packet(in, sizeof(in), from_addr);

            // don't bother about messages that obviously have no meaningful content
            if (inlen < MINIMR_DNS_HDR_SIZE){
                // just some waiting for responses
                std::this_thread::sleep_for(std::chrono::milliseconds(10));

                continue;
            }


            // the records names we're actually looking for (these should be in proper format)
            static uint8_t * filter_names[] = {
                    RR_A.name,
                    RR_SRV.name
            };
            static uint16_t nfilter_names = sizeof(filter_names) / sizeof(uint8_t *);

            static bool has_conflict;
            static struct {
                struct minimr_dns_rr * rr;
                uint8_t present;
                int8_t lexcmp;
            } ties[4] = {
                    {.rr = (struct minimr_dns_rr *)&RR_A},
                    {.rr = (struct minimr_dns_rr *)&RR_AAAA},
                    {.rr = (struct minimr_dns_rr *)&RR_TXT},
                    {.rr = (struct minimr_dns_rr *)&RR_SRV},
            };

            static int nties = 4;

            has_conflict = false;
            for(int i = 0; i < nties; i++){
                ties[i].present = 0;
            }

            static auto rrhandler = [](struct minimr_dns_hdr * hdr, minimr_dns_rr_section section, struct minimr_dns_rr_stat * rstat, uint8_t * msg, uint16_t msglen, uint8_t ifilter, void * from_addr) -> uint8_t {

                // other hosts that probe for the same name will send queries for that name which contain RR to be in the authority section (only)
                if ( (MINIMR_DNS_HDR_READ_FLAG1(msg) & MINIMR_DNS_HDR1_QR) == MINIMR_DNS_HDR1_QR_QUERY){

                    if (section == minimr_dns_rr_section_authority){

                        int i = 0;
                        for(; i < nties; i++) {
                            if (ties[i].rr->type == rstat->type){
                                break;
                            }
                        }

                        if (i >= nties) {
                            return MINIMR_CONTINUE;
                        }

                        has_conflict = true;

                        // I'm sure there are ways to make this in a more elegant way..
                        uint8_t tmp[512];
                        uint16_t tmplen = 0;

                        ties[i].rr->fun(minimr_dns_rr_fun_type_get_rr, ties[i].rr, tmp, &tmplen, sizeof(tmp), NULL);

                        struct minimr_dns_rr_stat tmprstat;

                        minimr_dns_extract_rr_stat(&tmprstat, tmp, &tmplen, sizeof(tmp));

                        ties[i].lexcmp = minimr_dns_rr_lexcmp(tmprstat.cache_class, tmprstat.type, &tmp[tmprstat.data_offset], tmprstat.dlength, rstat->cache_class, rstat->type, &msg[rstat->data_offset], rstat->dlength);


                    } else {
                        // shouldn't occur (I would think)
                    }

                } else {
                   state = State_Reconfigure;
                }

                return MINIMR_CONTINUE;
            };

            int res = minimr_parse_msg(in, inlen, filter_names, nfilter_names, NULL, rrhandler, &from_addr);

            if (res != MINIMR_OK){
                continue;
            }

            if (!has_conflict){
                continue;
            }

            for (int i = 0; i < nties; i++){
                if (ties[i].present){
                    if (ties[i].lexcmp > 0){
                        // we win, nothing to do
                    } else {
                        // we lose
                        state = State_ProbingLostTie;
                    }
                }
            }

            // we might still have lost..
            if (state == State_ProbingAwaitAnswers){
                if (nties < MINIMR_DNS_HDR_READ_NQ(in)){
                    // we lose...
                    state = State_ProbingLostTie;
                }
            }
        }

        if (state == State_ProbingLostTie){
            thread([&nprobe](){
                this_thread::sleep_for(std::chrono::seconds(1));

                // reset probing
                nprobe = 0;

                state = State_ProbingQuery;
            });

            // just consume any incoming data
            receive_udp_packet(in, sizeof(in), from_addr);
        }

        if (state == State_Reconfigure){

            // do whatever

            MINIMR_DEBUGF("We should reconfigure, but that's not implemented!\n");

            exit(EXIT_FAILURE);

            state = State_Init;
        }
        #endif // RECORDS_ARE_UNIQUE == 0

        if (state == State_Announce){

            // delegate announcement to other thread
            // our responder should not be blocked while multiple announcements occur
            std::thread([](){

                uint8_t out[2048];
                uint16_t outlen = 0;

                minimr_announce(records, NRECORDS, out, &outlen, sizeof(out), NULL);

                MINIMR_ASSERT(outlen > MINIMR_DNS_HDR_SIZE);

                send_udp_packet(out, outlen, Multicast);

                int delay_s = 1;

                for (int i = 0; i < NUMBER_OF_ANNOUNCEMENTS; i++){

                    // wait N second before announcing a second time (which we MUST or should)
                    std::this_thread::sleep_for(std::chrono::seconds(delay_s));

                    send_udp_packet(out, outlen, Multicast);

                    delay_s *= 2; // increase by at least a factor of 2

                }
            });

            state = State_Responding;
        }


        if (state == State_Responding){


            // now just wait for incoming messages
            inlen = receive_udp_packet(in, sizeof(in), from_addr);

            if (inlen == 0){
                // just some waiting for responses
                std::this_thread::sleep_for(std::chrono::milliseconds(10));

                continue;
            }

            uint8_t unicast_requested;

            uint8_t res = minimr_handle_queries(in, inlen, qstats, NQSTATS, records, NRECORDS, out, &outlen, sizeof(out), &unicast_requested);


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
                MINIMR_DEBUGF("other error %d!\n", res);
                continue;
            }

            MINIMR_DEBUGF("MINIMR_DNS_HDR2_RCODE_NOERROR\n");

            if (outlen > 0){
                send_udp_packet(out, outlen, unicast_requested ? Unicast : Multicast, from_addr);
            }
        }


    }


    return 0;
}