//
// Created by Philip Tschiemer on 06.07.20.
//
#include "minimrsimple.h"
#include "minimr.h"

#if MINIMR_SIMPLE_INTERFACE_ENABLED == 1


#include <stdarg.h>

static uint8_t simple_probe_rrhandler(struct minimr_dns_hdr * hdr, minimr_rr_section section, struct minimr_rr_stat * rstat, uint8_t * msg, uint16_t msglen, void * user_data);
static int32_t simple_rr_handler(minimr_rr_fun type, struct minimr_rr *rr, ...);


#if MINIMR_RR_TYPE_A_DEFAULT
minimr_rr_a minimr_simple_rr_a = {
    .type = MINIMR_DNS_TYPE_A,
    .ttl = MINIMR_DEFAULT_TTL,
    .handler = simple_rr_handler,

#ifdef MINIMR_SIMPLE_HOSTNAME
    .name = MINIMR_SIMPLE_HOSTNAME
#endif

#ifdef MINIMR_SIMPLE_IPV4
    .ipv4 = MINIMR_SIMPLE_IPV4
#endif
};
#endif

#if MINIMR_RR_TYPE_AAAA_DEFAULT
minimr_rr_aaaa minimr_simple_rr_aaaa = {
    .type = MINIMR_DNS_TYPE_A,
    .ttl = MINIMR_DEFAULT_TTL,
    .handler = simple_rr_handler,

#ifdef MINIMR_SIMPLE_HOSTNAME
    .name = MINIMR_SIMPLE_HOSTNAME
#endif

#ifdef MINIMR_SIMPLE_IPV6
    .ipv6 = MINIMR_SIMPLE_IPV6
#endif

};
#endif


#if MINIMR_RR_TYPE_SRV_DEFAULT
minimr_rr_srv minimr_simple_rr_srv = {
    .type = MINIMR_DNS_TYPE_SRV,
    .ttl = MINIMR_DEFAULT_TTL,
    .handler = simple_rr_handler,

#ifdef MINIMR_SIMPLE_SERVICE_NAME
    .name = MINIMR_SIMPLE_SERVICE_NAME,
#endif

#ifdef MINIMR_SIMPLE_SERVICE_WEIGHT
    .weight = MINIMR_SIMPLE_SERVICE_WEIGHT,
#else
    .weight = 0,
#endif

#ifdef MINIMR_SIMPLE_SERVICE_PRIORITY
    .priority = MINIMR_SIMPLE_SERVICE_PRIORITY,
#else
    .priority = 0,
#endif

#ifdef MINIMR_SIMPLE_SERVICE_PORT
    .port = MINIMR_SIMPLE_SERVICE_PORT,
#else
    .port = 0,
#endif

#ifdef MINIMR_SIMPLE_HOSTNAME
    .target = MINIMR_SIMPLE_HOSTNAME
#endif
};
#endif

#if MINIMR_RR_TYPE_TXT_DEFAULT
minimr_rr_txt minimr_simple_rr_txt = {
    .type = MINIMR_DNS_TYPE_TXT,
    .ttl = MINIMR_DEFAULT_TTL,
    .handler = simple_rr_handler,

#ifdef MINIMR_SIMPLE_SERVICE_TXT
    .txt = MINIMR_SIMPLE_SERVICE_TXT
#endif
};
#endif


#if MINIMR_RR_TYPE_PTR_DEFAULT
minimr_rr_ptr minimr_simple_rr_ptr = {
        .type = MINIMR_DNS_TYPE_PTR,
        .ttl = MINIMR_DEFAULT_TTL,
        .handler = simple_rr_handler,

#ifdef MINIMR_SIMPLE_SERVICEPTR
        .name = MINIMR_SIMPLE_SERVICEPTR,
#endif

#ifdef MINIMR_SIMPLE_HOSTNAME
        .domain = MINIMR_SIMPLE_HOSTNAME
#endif

};
#endif

struct minimr_rr * minimr_simple_rr_set[MINIMR_RR_TYPE_DEFAULT_COUNT] = {
#if MINIMR_RR_TYPE_A_DEFAULT
        (struct minimr_rr *)&minimr_simple_rr_a,
#endif
#if MINIMR_RR_TYPE_AAAA_DEFAULT
        (struct minimr_rr *)&minimr_simple_rr_aaaa,
#endif
#if MINIMR_RR_TYPE_SRV_DEFAULT
        (struct minimr_rr *)&minimr_simple_rr_srv,
#endif
#if MINIMR_RR_TYPE_TXT_DEFAULT
        (struct minimr_rr *)&minimr_simple_rr_txt,
#endif
#if MINIMR_RR_TYPE_PTR_DEFAULT
        (struct minimr_rr *)&minimr_simple_rr_ptr,
#endif
};


typedef struct {
    uint8_t seen;
    int8_t cmp;
    struct minimr_rr * rr;
} simple_tie_t;

typedef struct {
    uint8_t conflict;
    uint8_t nrecords;
    uint8_t nties;
    simple_tie_t ties[MINIMR_RR_TYPE_DEFAULT_COUNT];
} simple_tie_breaker_t;

static volatile simple_state_t simple_state;

static uint8_t simple_announcement_count;
static uint8_t simple_probe_count;

static struct minimr_simple_init_st simple_cfg;

simple_state_t minimr_simple_get_state()
{
    return simple_state;
}

void minimr_simple_set_ips(uint8_t * ipv4, uint16_t * ipv6)
{
#if MINIMR_RR_TYPE_A_DEFAULT
    if (ipv4 == NULL){
        minimr_simple_rr_set[MINIMR_SIMPLE_A_INDEX] = NULL;
    } else {
        minimr_simple_rr_a.ipv4[0] = ipv4[0];
        minimr_simple_rr_a.ipv4[1] = ipv4[1];
        minimr_simple_rr_a.ipv4[2] = ipv4[2];
        minimr_simple_rr_a.ipv4[3] = ipv4[3];
        minimr_simple_rr_set[MINIMR_SIMPLE_A_INDEX] = (struct minimr_rr *)&minimr_simple_rr_a;
    }
#endif

#if MINIMR_RR_TYPE_AAAA_DEFAULT
    if (ipv6 == NULL){
        minimr_simple_rr_set[MINIMR_SIMPLE_AAAA_INDEX] = NULL;
    } else {
        minimr_simple_rr_aaaa.ipv6[0] = ipv6[0];
        minimr_simple_rr_aaaa.ipv6[1] = ipv6[1];
        minimr_simple_rr_aaaa.ipv6[2] = ipv6[2];
        minimr_simple_rr_aaaa.ipv6[3] = ipv6[3];
        minimr_simple_rr_aaaa.ipv6[4] = ipv6[4];
        minimr_simple_rr_aaaa.ipv6[5] = ipv6[5];
        minimr_simple_rr_aaaa.ipv6[6] = ipv6[6];
        minimr_simple_rr_aaaa.ipv6[7] = ipv6[7];
        minimr_simple_rr_set[MINIMR_SIMPLE_AAAA_INDEX] = (struct minimr_rr *)&minimr_simple_rr_aaaa;
    }
#endif
}


void minimr_simple_init(struct minimr_simple_init_st * init_st)
{
    MINIMR_ASSERT(init_st != NULL);
    MINIMR_ASSERT(init_st->probe_or_not == 0 || init_st->probing_end_timer != NULL);
    MINIMR_ASSERT(init_st->probe_or_not == 0 || init_st->reconfiguration_needed != NULL);
    MINIMR_ASSERT(init_st->announcement_count <= 8);
    MINIMR_ASSERT(init_st->announcement_count < 2 || init_st->announcement_timer != NULL);

    simple_cfg.processing_required = init_st->processing_required;

    simple_cfg.probe_or_not = init_st->probe_or_not;
    simple_cfg.probing_end_timer = init_st->probing_end_timer;
    simple_cfg.reconfiguration_needed = init_st->reconfiguration_needed;

    simple_cfg.announcement_count = init_st->announcement_count;
    simple_cfg.announcement_timer = init_st->announcement_timer;

#if MINIMR_TIMESTAMP_USE
    MINIMR_ASSERT(init_st->time_now != NULL);
    MINIMR_ASSERT(init_st->time_cpy != NULL);
    MINIMR_ASSERT(init_st->time_diff_sec != NULL);

    simple_cfg.time_now = init_st->time_now;
    simple_cfg.time_cpy = init_st->time_cpy;
    simple_cfg.time_diff_sec = init_st->time_diff_sec;
#endif //MINIMR_TIMESTAMP_USE

    simple_state = simple_state_init;

#if MINIMR_RR_TYPE_A_DEFAULT
    minimr_name_normalize(minimr_simple_rr_a.name, &minimr_simple_rr_a.name_length);
#endif
#if MINIMR_RR_TYPE_AAAA_DEFAULT
    minimr_name_normalize(minimr_simple_rr_aaaa.name, &minimr_simple_rr_aaaa.name_length);
#endif
#if MINIMR_RR_TYPE_SRV_DEFAULT
    minimr_name_normalize(minimr_simple_rr_srv.name, &minimr_simple_rr_srv.name_length);
    minimr_name_normalize(minimr_simple_rr_srv.target, &minimr_simple_rr_srv.target_length);
#endif
#if MINIMR_RR_TYPE_TXT_DEFAULT
    minimr_name_normalize(minimr_simple_rr_txt.name, &minimr_simple_rr_txt.name_length);
    minimr_txt_normalize(minimr_simple_rr_txt.txt, &minimr_simple_rr_txt.txt_length, MINIMR_SIMPLE_SERVICE_TXTMARKER);
#endif
#if MINIMR_RR_TYPE_PTR_DEFAULT
    minimr_name_normalize(minimr_simple_rr_ptr.name, &minimr_simple_rr_ptr.name_length);
    minimr_name_normalize(minimr_simple_rr_ptr.domain, &minimr_simple_rr_ptr.domain_length);
#endif
}

void minimr_simple_start()
{
    // only act when in init or stopped state
    if (simple_state != simple_state_init && simple_state != simple_state_stopped){
        return;
    }

    if (simple_cfg.probe_or_not){
        simple_state = simple_state_probe;
    } else {
        simple_state = simple_state_announce;
    }

    if (simple_cfg.processing_required != NULL){
        simple_cfg.processing_required();
    }
}

int32_t minimr_simple_stop(uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen)
{
    simple_state = simple_state_stopped;

    if (outmsg == NULL || outmsgmaxlen == 0){
        return MINIMR_OK;
    }

    return minimr_simple_terminate_msg(outmsg, outmsglen, outmsgmaxlen);
}

void minimr_simple_probing_end_timer_callback(uint8_t * outmsg, uint16_t * outmsglen, uint16_t outmsgmaxlen)
{
    // if not in the right state, do nothing
    if (simple_state != simple_state_await_probe_response){
        return;
    }

    // after the third probe we're ok!
    if (simple_probe_count >= 3){
        simple_state = simple_state_responding;
        return;
    }

    simple_probe_count++;

    minimr_simple_probequery_msg(outmsg, outmsglen, outmsgmaxlen, 0);
}

int32_t minimr_simple_announce(uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen)
{
    // cancel action if fsm was stopped
    if (simple_state == simple_state_stopped){
        return MINIMR_ABORT;
    }

    // is there a way to set a timer for the next announcement?
    if (simple_cfg.announcement_timer != NULL){

        if (simple_announcement_count < simple_cfg.announcement_count){
            // in fsm announcement count is initialized with 0
            // exponential increment in delay times
            simple_cfg.announcement_timer(1 << simple_announcement_count);

            simple_announcement_count++;
        }

    }

    return minimr_simple_announce_msg(outmsg, outmsglen, outmsgmaxlen);
}

int32_t minimr_simple_fsm(uint8_t *msg, uint16_t msglen, uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen, uint8_t *unicast_requested)
{
    if (simple_state == simple_state_init){
        // wait for explicit start command
        return MINIMR_OK;
    }

    if (simple_state == simple_state_stopped){
        // wait for explicit (re-)start command
        return MINIMR_OK;
    }

    if (simple_state == simple_state_probe){

        int32_t res = minimr_simple_probequery_msg(outmsg, outmsglen, outmsgmaxlen, 0); // 0 -> no unicast requested

        if (res != MINIMR_OK){
            MINIMR_DEBUGF("initial probe query failed, stopping!\n");
            simple_state = simple_state_stopped;
        } else {
            simple_state = simple_state_await_probe_response;

            simple_probe_count = 1;
            simple_cfg.probing_end_timer(250);
        }

        return res;
    }

    if (simple_state == simple_state_await_probe_response){

        if (msg != NULL && msglen > 0){
            struct minimr_filter filters[2];

            filters[0].fclass = MINIMR_DNS_CLASS_IN;
            filters[0].type = MINIMR_DNS_TYPE_ANY;

            if (0){

            }
#if MINIMR_RR_TYPE_A_DEFAULT
            else if (minimr_simple_rr_set[MINIMR_SIMPLE_A_INDEX] != NULL){
                filters[0].name = minimr_simple_rr_a.name;
                filters[0].name_length = minimr_simple_rr_a.name_length;
            }
#elif MINIMR_RR_TYPE_AAAA_DEFAULT
            else if (minimr_simple_rr_set[MINIMR_SIMPLE_AAAA_INDEX] != NULL){
                filters[0].name = minimr_simple_rr_aaaa.name;
                filters[0].name_length = minimr_simple_rr_aaaa.name_length;
            }
#else
#error No A/AAAA record defined!
#endif
            else {
                MINIMR_DEBUGF("No valid A/AAAA set through set_ips(..) - stopping!\n");
                simple_state = simple_state_stopped;
                return MINIMR_NOT_OK;
            }

            uint16_t nfilters = 1;

            filters[1].fclass = MINIMR_DNS_CLASS_IN;
            filters[1].type = MINIMR_DNS_TYPE_ANY;

#if MINIMR_RR_TYPE_SRV_DEFAULT
            filters[1].name = minimr_simple_rr_srv.name;
            filters[1].name_length = minimr_simple_rr_srv.name_length;
            nfilters++;
#elif MINIMR_RR_TYPE_TXT_DEFAULT
            filters[1].name = minimr_simple_rr_srv.name;
            filters[1].name_length = minimr_simple_rr_srv.name_length;
            nfilters++;
#endif

            int32_t res = minimr_parse_msg(msg, msglen, minimr_msgtype_any, NULL, NULL, 0, simple_probe_rrhandler, filters, nfilters, NULL);

            if (res != MINIMR_OK){
                MINIMR_DEBUGF("parse failed %d\n", res);
            }

            return MINIMR_OK;
        }
    }

    if (simple_state == simple_state_announce){

        simple_announcement_count = 0;

        int32_t res = minimr_simple_announce(outmsg, outmsglen, outmsgmaxlen);

        if (res != MINIMR_OK){
            MINIMR_DEBUGF("initial announcement failed, stopping!\n");
            simple_state = simple_state_stopped;
        } else {
            simple_state = simple_state_responding;
        }

        return res;
    }

    if (simple_state == simple_state_responding){
        if (msg != NULL && msglen > 0){
            return minimr_simple_query_response_msg(msg, msglen, outmsg, outmsglen, outmsgmaxlen, unicast_requested);
        }

        return MINIMR_OK;
    }

    return MINIMR_OK;
}

int32_t minimr_simple_probequery_msg(
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
        uint8_t request_unicast
)
{
    uint8_t * hostname = NULL;
    uint8_t * servicename = NULL;

    if (0){

    }
#if MINIMR_RR_TYPE_A_DEFAULT
    // check if
    else if (minimr_simple_rr_set[0] != NULL){
        hostname = minimr_simple_rr_a.name;
    }
#elif MINIMR_RR_TYPE_AAAA_DEFAULT
    else if (minimr_simple_rr_set[MINIMR_RR_TYPE_A_DEFAULT] != NULL){
        hostname = minimr_simple_rr_aaaa.name;
    }
#else
#error Hmmm no A/AAAA record defined
#endif
    else {
        MINIMR_DEBUGF("No A/AAAA record is active (set through set_ips(..)\n");
        return MINIMR_NOT_OK;
    }

    // only probe for servicename if it has been defined.
#if MINIMR_RR_TYPE_SRV_DEFAULT
    servicename = minimr_simple_rr_srv.name;
#elif MINIMR_RR_TYPE_TXT_DEFAULT
    servicename = minimr_simple_rr_txt.name;
#endif


#if MINIMR_RR_TYPE_PTR_DEFAULT
    // do not add PTR record to probequery
    void * ptr = minimr_simple_rr_set[MINIMR_SIMPLE_PTR_INDEX];
    minimr_simple_rr_set[MINIMR_SIMPLE_PTR_INDEX] = NULL;
#endif

    int32_t res = minimr_probequery_msg(hostname, servicename, minimr_simple_rr_set, MINIMR_RR_TYPE_DEFAULT_COUNT, outmsg, outmsglen, outmsgmaxlen, request_unicast,  NULL);


#if MINIMR_RR_TYPE_PTR_DEFAULT
    // restore previous state
    minimr_simple_rr_set[MINIMR_SIMPLE_PTR_INDEX] = ptr;
#endif

    return res;
}

int32_t minimr_simple_announce_msg(
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen
)
{
    return minimr_announce_msg(minimr_simple_rr_set, MINIMR_RR_TYPE_DEFAULT_COUNT, outmsg, outmsglen, outmsgmaxlen, NULL);
}

int32_t minimr_simple_terminate_msg(
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen
)
{
    return minimr_terminate_msg(minimr_simple_rr_set, MINIMR_RR_TYPE_DEFAULT_COUNT, outmsg, outmsglen, outmsgmaxlen, NULL);
}

int32_t minimr_simple_query_response_msg(
        uint8_t *msg, uint16_t msglen,
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
        uint8_t *unicast_requested
)
{

    struct minimr_query_stat qstats[MINIMR_RR_TYPE_DEFAULT_COUNT];

    return minimr_query_response_msg(
        msg, msglen,
        qstats, MINIMR_RR_TYPE_DEFAULT_COUNT,
        minimr_simple_rr_set, MINIMR_RR_TYPE_DEFAULT_COUNT,
        outmsg, outmsglen, outmsgmaxlen,
        unicast_requested,
        NULL
    );
}

uint8_t simple_probe_rrhandler(struct minimr_dns_hdr * hdr, minimr_rr_section section, struct minimr_rr_stat * rstat, uint8_t * msg, uint16_t msglen, void * user_data)
{
    // in case another (authorative) host is responding to our probequery we already pretty much lost
    if ((hdr->flags[0] & MINIMR_DNS_HDR1_QR) == MINIMR_DNS_HDR1_QR_REPLY){

        // only care about authorative responses
        if ( (hdr->flags[0] & MINIMR_DNS_HDR1_AA) == MINIMR_DNS_HDR1_AA){

            simple_state = simple_state_stopped;

            simple_cfg.reconfiguration_needed();

            return MINIMR_ABORT;
        }

        return MINIMR_CONTINUE;
    }

    //so it's a query and we might have to do the whole tie-breaking procedure..

    //but (because actual tiebreaking as specified by the RFC is beyond this framework) instead we just tell the host
    //to reconfigure..

    simple_state = simple_state_stopped;

    simple_cfg.reconfiguration_needed();

    return MINIMR_ABORT;
}

int32_t simple_rr_handler(minimr_rr_fun fun, struct minimr_rr *rr, ...)
{
    MINIMR_ASSERT(MINIMR_RR_FUN_IS_VALID(fun));

    va_list args;
    va_start(args, rr);

    struct minimr_query_stat * qstat;
    uint8_t * outmsg;
    uint16_t * outmsglen;
    uint16_t outmsgmaxlen;
    uint16_t * nrr;
    uint8_t unicast_requested;
    void * user_data;

    //
    uint16_t rclass;
    uint16_t rtype;
    uint8_t * rdata;
    uint16_t rdlength;

    switch(fun){


        //minimr_rr_fun_handler( minimquery_get_*, struct minimr_rr * rr, struct minimr_query_stat * qstat, uint8_t * outmsg, uint16_t * outlen, uint16_t outmsgmaxlen, uint16_t * nrr, void * user_data)
        case minimr_rr_fun_query_get_rr:
        case minimr_rr_fun_query_get_authority_rrs:
        case minimr_rr_fun_query_get_extra_rrs:
            qstat = (struct minimr_query_stat *)va_arg(args, void*);
            // INTENDED FALL THROUGH

        //minimr_rr_fun_handler( minimr_rr_fun_get_rr, struct minimr_rr * rr,  uint8_t * outmsg, uint16_t * outlen, uint16_t outmsgmaxlen, uint16_t * nrr, void * user_data)
        //minimr_rr_fun_handler( minimr_rr_fun_announce_get_*, uint8_t * outmsg, uint16_t * outlen, uint16_t outmsgmaxlen, uint16_t * nrr, void * user_data)
        case minimr_rr_fun_get_rr:
        case minimr_rr_fun_announce_get_rr:
        case minimr_rr_fun_announce_get_extra_rrs:
            outmsg = va_arg(args, uint8_t *);
            outmsglen = va_arg(args, uint16_t *);
            outmsgmaxlen = va_arg(args, int); // uint16_t will be promoted to int
            nrr = va_arg(args, uint16_t *);
            // INTENDED FALL THROUGH

        // minimr_rr_fun_handler( minimr_rr_fun_query_respond_to, struct minimr_rr * rr, void * user_data);
        case minimr_rr_fun_query_respond_to:
            user_data = va_arg(args, void*);
            break;


        case minimr_rr_fun_lexcmp:
            rclass = va_arg(args, int32_t);
            rtype = va_arg(args, int32_t);
            rdata = va_arg(args, uint8_t*);
            rdlength = va_arg(args, int32_t);
            user_data = va_arg(args, void*);
            break;
    }

    va_end(args);


    if (fun == minimr_rr_fun_query_respond_to){

#if MINIMR_TIMESTAMP_USE
        MINIMR_TIMESTAMP_TYPE now;
        simple_cfg.time_now(&now);

        // if already answered within the last second, then don't answer
        if (simple_cfg.time_diff_sec(&rr->last_responded, &now) > 1){
            return MINIMR_DO_NOT_RESPOND;
        }

        simple_cfg.time_cpy(&rr->last_responded, &now);
#endif

        return MINIMR_RESPOND;
    }

    // combining the three function types is safe only because we do not use qstat here
    // note that by treating announce_get_rr identical to get_rr all records will be in the answer section of the
    // announce message (and none will be passed in th extra RR section; see below)
    if (fun == minimr_rr_fun_query_get_rr || fun == minimr_rr_fun_get_rr || fun == minimr_rr_fun_announce_get_rr){

        if ( 0

#if MINIMR_RR_TYPE_A_DEFAULT
             || (rr->type == MINIMR_DNS_TYPE_A && outmsgmaxlen < MINIMR_DNS_RR_A_SIZE(rr->name_length))
#endif
#if MINIMR_RR_TYPE_AAAA_DEFAULT
             || (rr->type == MINIMR_DNS_TYPE_AAAA && outmsgmaxlen < MINIMR_DNS_RR_AAAA_SIZE(rr->name_length))
#endif
#if MINIMR_RR_TYPE_PTR_DEFAULT
             || (rr->type == MINIMR_DNS_TYPE_PTR && outmsgmaxlen < MINIMR_DNS_RR_PTR_SIZE(rr->name_length, ((minimr_rr_ptr*)rr)->domain_length))
#endif
#if MINIMR_RR_TYPE_SRV_DEFAULT
             || (rr->type == MINIMR_DNS_TYPE_SRV && outmsgmaxlen < MINIMR_DNS_RR_SRV_SIZE(rr->name_length, ((minimr_rr_srv*)rr)->target_length))
#endif
#if MINIMR_RR_TYPE_TXT_DEFAULT
             || (rr->type == MINIMR_DNS_TYPE_TXT && outmsgmaxlen < MINIMR_DNS_RR_TXT_SIZE(rr->name_length, ((minimr_rr_txt*)rr)->txt_length))
#endif
                ) {

            return MINIMR_NOT_OK;
        }

        uint16_t l = *outmsglen;

        // our macro always sets the cache flush flag
        MINIMR_DNS_RR_WRITE_COMMON(outmsg, l, rr->name, rr->name_length, rr->type, rr->cache_class, rr->ttl);

        if (0){
            // :)
        }
#if MINIMR_RR_TYPE_A_DEFAULT
        else if (rr->type == MINIMR_DNS_TYPE_A) {
            MINIMR_DNS_RR_WRITE_A_BODY(outmsg, l, ((minimr_rr_a*)rr)->ipv4);
        }
#endif
#if MINIMR_RR_TYPE_AAAA_DEFAULT
        else if (rr->type == MINIMR_DNS_TYPE_AAAA) {
            MINIMR_DNS_RR_WRITE_A_BODY(outmsg, l, ((minimr_rr_aaaa*)rr)->ipv6);
        }
#endif
#if MINIMR_RR_TYPE_PTR_DEFAULT
        else if (rr->type == MINIMR_DNS_TYPE_PTR) {
            MINIMR_DNS_RR_WRITE_PTR_BODY(outmsg, l, ((minimr_rr_ptr*)rr)->domain, ((minimr_rr_ptr*)rr)->domain_length);
        }
#endif
#if MINIMR_RR_TYPE_SRV_DEFAULT
        else if (rr->type == MINIMR_DNS_TYPE_SRV) {
            MINIMR_DNS_RR_WRITE_SRV_BODY(outmsg, l, ((minimr_rr_srv*)rr)->priority, ((minimr_rr_srv*)rr)->weight, ((minimr_rr_srv*)rr)->port, ((minimr_rr_srv*)rr)->target, ((minimr_rr_srv*)rr)->target_length);
        }
#endif
#if MINIMR_RR_TYPE_TXT_DEFAULT
        else if (rr->type == MINIMR_DNS_TYPE_TXT) {
            MINIMR_DNS_RR_WRITE_TXT_BODY(outmsg, l, ((minimr_rr_txt*)rr)->txt, ((minimr_rr_txt*)rr)->txt_length);
        }
#endif
        else {
            MINIMR_DEBUGF("Unrecognized record type: %d", rr->type);
            return MINIMR_NOT_OK;
        }

        *outmsglen = l;
        if (nrr != NULL){
            *nrr = 1;
        }

        return MINIMR_OK;
    }

    if (fun == minimr_rr_fun_query_get_authority_rrs){

        // no auth to add

        return MINIMR_OK;
    }

    // combining these two function types i
    if (fun == minimr_rr_fun_query_get_extra_rrs){

        uint16_t n = 0;

#if MINIMR_RR_TYPE_A_DEFAULT && MINIMR_RR_TYPE_AAAA_DEFAULT
        // if type A was queried but we also have an AAAA type (which is set) add the AAAA record as extra
        if (rr->type == MINIMR_DNS_TYPE_A && qstat->type == MINIMR_DNS_TYPE_AAAA && minimr_simple_rr_set[MINIMR_SIMPLE_A_INDEX] != NULL){
            if (simple_rr_handler(minimr_rr_fun_get_rr, (struct minimr_rr *)&minimr_simple_rr_aaaa, qstat, outmsg, outmsglen, outmsgmaxlen, NULL) != MINIMR_OK) return MINIMR_NOT_OK;
            n++;
        }
        // and vice versa
        if (rr->type == MINIMR_DNS_TYPE_AAAA && qstat->type == MINIMR_DNS_TYPE_A && minimr_simple_rr_set[MINIMR_SIMPLE_AAAA_INDEX] != NULL){
            if (simple_rr_handler(minimr_rr_fun_get_rr, (struct minimr_rr *)&minimr_simple_rr_a, qstat, outmsg, outmsglen, outmsgmaxlen, NULL) != MINIMR_OK) return MINIMR_NOT_OK;
            n++;
        }
#endif //MINIMR_RR_TYPE_A_DEFAULT && MINIMR_RR_TYPE_AAAA_DEFAULT

#if MINIMR_RR_TYPE_PTR_DEFAULT
        // if type == PTR then the query was for unknown services (ie PTRs)
        if (rr->type == MINIMR_DNS_TYPE_PTR){

            // this only works because we the actual records are referencable
#if MINIMR_RR_TYPE_A_DEFAULT
            // only pass A record if set
            if (minimr_simple_rr_set[MINIMR_SIMPLE_A_INDEX] != NULL){
                if (simple_rr_handler(minimr_rr_fun_get_rr, (struct minimr_rr *)&minimr_simple_rr_a, qstat, outmsg, outmsglen, outmsgmaxlen, NULL) != MINIMR_OK) return MINIMR_NOT_OK;
                n++;
            }
#endif
#if MINIMR_RR_TYPE_AAAA_DEFAULT
            // only pass AAAA record if set
            if (minimr_simple_rr_set[MINIMR_SIMPLE_AAAA_INDEX] != NULL){
                if (simple_rr_handler(minimr_rr_fun_get_rr, (struct minimr_rr *)&minimr_simple_rr_aaaa, qstat, outmsg, outmsglen, outmsgmaxlen, NULL) != MINIMR_OK) return MINIMR_NOT_OK;
                n++;
            }
#endif
#if MINIMR_RR_TYPE_SRV_DEFAULT
            if (minimr_simple_rr_set[MINIMR_SIMPLE_SRV_INDEX] != NULL){
                if (simple_rr_handler(minimr_rr_fun_get_rr, (struct minimr_rr *)&minimr_simple_rr_srv, qstat, outmsg, outmsglen, outmsgmaxlen, NULL) != MINIMR_OK) return MINIMR_NOT_OK;
                n++;
            }
#endif
#if MINIMR_RR_TYPE_TXT_DEFAULT
            if (minimr_simple_rr_set[MINIMR_SIMPLE_TXT_INDEX] != NULL) {
                if (simple_rr_handler(minimr_rr_fun_get_rr, (struct minimr_rr *) &minimr_simple_rr_txt, qstat, outmsg,
                                      outmsglen, outmsgmaxlen, NULL) != MINIMR_OK)
                    return MINIMR_NOT_OK;
                n++;
            }
#endif
        }
#endif //MINIMR_RR_TYPE_PTR_DEFAULT


        if (nrr != NULL){
            *nrr = n;
        }

        return MINIMR_OK;
    }

    if (fun == minimr_rr_fun_announce_get_extra_rrs){
        // do nothing (note: to keep things simple all announcement records will be in the normal answer section and not in the extra RR section; see above)
        return MINIMR_OK;
    }

    // lexcmp is not used but the code will be left here for reference
//    if (fun == minimr_rr_fun_lexcmp){
//
//
//        if ( (rr->cache_class & MINIMR_DNS_QCLASS) < (rclass & MINIMR_DNS_QCLASS)) return -1;
//        if ( (rr->cache_class & MINIMR_DNS_QCLASS) > (rclass & MINIMR_DNS_QCLASS)) return 1;
//
//        if ( rr->type < rtype) return -1;
//        if ( rr->type > rtype ) return 1;
//
//        if (rr->type == MINIMR_DNS_TYPE_A){
//
//            // if rdlength is faulty, we win
//            if (rdlength != 4){
//                return -1;
//            }
//
//            // we should do sanity checking here for rdlength match
//            if (((minimr_rr_a*)rr)->ipv4[0] < rdata[0]) return -1;
//            if (((minimr_rr_a*)rr)->ipv4[0] > rdata[0]) return 1;
//            if (((minimr_rr_a*)rr)->ipv4[1] < rdata[1]) return -1;
//            if (((minimr_rr_a*)rr)->ipv4[1] > rdata[1]) return 1;
//            if (((minimr_rr_a*)rr)->ipv4[2] < rdata[2]) return -1;
//            if (((minimr_rr_a*)rr)->ipv4[2] > rdata[2]) return 1;
//            if (((minimr_rr_a*)rr)->ipv4[3] < rdata[3]) return -1;
//            if (((minimr_rr_a*)rr)->ipv4[3] > rdata[3]) return 1;
//
//            return 0;
//        }
//
//        if (rr->type == MINIMR_DNS_TYPE_AAAA){
//
//            // if rdlength is faulty, we win
//            if (rdlength != 16){
//                return -1;
//            }
//
//            uint16_t u16;
//
//            u16 = (rdata[0] << 8) | rdata[1];
//            if (((minimr_rr_aaaa*)rr)->ipv6[0] < u16) return -1;
//            if (((minimr_rr_aaaa*)rr)->ipv6[0] > u16) return 1;
//            u16 = (rdata[2] << 8) | rdata[3];
//            if (((minimr_rr_aaaa*)rr)->ipv6[1] < u16) return -1;
//            if (((minimr_rr_aaaa*)rr)->ipv6[1] > u16) return 1;
//            u16 = (rdata[4] << 8) | rdata[5];
//            if (((minimr_rr_aaaa*)rr)->ipv6[2] < u16) return -1;
//            if (((minimr_rr_aaaa*)rr)->ipv6[2] > u16) return 1;
//            u16 = (rdata[6] << 8) | rdata[7];
//            if (((minimr_rr_aaaa*)rr)->ipv6[3] < u16) return -1;
//            if (((minimr_rr_aaaa*)rr)->ipv6[3] > u16) return 1;
//            u16 = (rdata[8] << 8) | rdata[9];
//            if (((minimr_rr_aaaa*)rr)->ipv6[4] < u16) return -1;
//            if (((minimr_rr_aaaa*)rr)->ipv6[4] > u16) return 1;
//            u16 = (rdata[10] << 8) | rdata[11];
//            if (((minimr_rr_aaaa*)rr)->ipv6[5] < u16) return -1;
//            if (((minimr_rr_aaaa*)rr)->ipv6[5] > u16) return 1;
//            u16 = (rdata[12] << 8) | rdata[13];
//            if (((minimr_rr_aaaa*)rr)->ipv6[6] < u16) return -1;
//            if (((minimr_rr_aaaa*)rr)->ipv6[6] > u16) return 1;
//            u16 = (rdata[14] << 8) | rdata[15];
//            if (((minimr_rr_aaaa*)rr)->ipv6[7] < u16) return -1;
//            if (((minimr_rr_aaaa*)rr)->ipv6[7] > u16) return 1;
//
//            return 0;
//        }
//
//        if (rr->type == MINIMR_DNS_TYPE_SRV){
//
//            // if rdlength is faulty, we win
//            if (rdlength < 6){
//                return -1;
//            }
//
//            uint16_t u16;
//
//            u16 = (rdata[0] << 8) | rdata[1];
//            if (((minimr_rr_srv*)rr)->priority < u16) return -1;
//            if (((minimr_rr_srv*)rr)->priority > u16) return 1;
//
//            u16 = (rdata[2] << 8) | rdata[3];
//            if (((minimr_rr_srv*)rr)->weight < u16) return -1;
//            if (((minimr_rr_srv*)rr)->weight > u16) return 1;
//
//            u16 = (rdata[4] << 8) | rdata[5];
//            if (((minimr_rr_srv*)rr)->port < u16) return -1;
//            if (((minimr_rr_srv*)rr)->port > u16) return 1;
//
//            uint16_t len = ((minimr_rr_srv*)rr)->target_length + 6 < rdlength ? ((minimr_rr_srv*)rr)->target_length : rdlength - 6;
//
//            for (uint16_t i = 0, j = 6; i < len; i++, j++){
//                if (((minimr_rr_srv*)rr)->target[i] < rdata[j]) return -1;
//                if (((minimr_rr_srv*)rr)->target[i] > rdata[j]) return 1;
//            }
//
//            if (((minimr_rr_srv*)rr)->target_length + 6 < rdlength) return -1;
//            if (((minimr_rr_srv*)rr)->target_length + 6 > rdlength) return 1;
//
//            return 0;
//        }
//
//        if (rr->type == MINIMR_DNS_TYPE_TXT){
//            uint16_t len = ((minimr_rr_txt*)rr)->txt_length < rdlength ? ((minimr_rr_txt*)rr)->txt_length : rdlength;
//
//            for (uint16_t i = 0; i < len; i++){
//                if (((minimr_rr_txt*)rr)->txt[i] < rdata[i]) return -1;
//                if (((minimr_rr_txt*)rr)->txt[i] > rdata[i]) return 1;
//            }
//
//            if (((minimr_rr_txt*)rr)->txt_length < rdlength) return -1;
//            if (((minimr_rr_txt*)rr)->txt_length > rdlength) return 1;
//
//            return 0;
//        }
//
//
//        if (rr->type == MINIMR_DNS_TYPE_PTR){
//            // we shouldnt need to compare these..
//        }
//
//        return 0;
//    }

    return MINIMR_OK; // ...
}



#endif //#if MINIMR_SIMPLE_INTERFACE_ENABLED == 1