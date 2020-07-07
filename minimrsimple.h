//
// Created by Philip Tschiemer on 06.07.20.
//

#ifndef MINIMR_MINIMRSIMPLE_H
#define MINIMR_MINIMRSIMPLE_H

#include "minimr.h"

#if MINIMR_SIMPLE_INTERFACE_ENABLED == 1

#ifdef __cplusplus
extern "C" {
#endif

#if MINIMR_RR_TYPE_DEFAULT_COUNT < 1
#error Please define at least one default type to use the minimsimple interface
#endif

#if MINIMR_RR_TYPE_A_DEFAULT
extern minimr_rr_a minimr_simple_rr_a;
#define MINIMR_SIMPLE_A_INDEX 0
#endif

#if MINIMR_RR_TYPE_AAAA_DEFAULT
extern minimr_rr_aaaa minimr_simple_rr_aaaa;
#define MINIMR_SIMPLE_AAAA_INDEX MINIMR_RR_TYPE_A_DEFAULT
#endif

#if MINIMR_RR_TYPE_SRV_DEFAULT
extern minimr_rr_srv minimr_simple_rr_srv;
#define MINIMR_SIMPLE_SRV_INDEX (MINIMR_RR_TYPE_A_DEFAULT + MINIMR_RR_TYPE_AAAA_DEFAULT)
#endif

#if MINIMR_RR_TYPE_TXT_DEFAULT
extern minimr_rr_txt minimr_simple_rr_txt;
#define MINIMR_SIMPLE_TXT_INDEX (MINIMR_RR_TYPE_A_DEFAULT + MINIMR_RR_TYPE_AAAA_DEFAULT + MINIMR_RR_TYPE_SRV_DEFAULT)
#endif

#if MINIMR_RR_TYPE_PTR_DEFAULT
extern minimr_rr_ptr minimr_simple_rr_ptr;
#define MINIMR_SIMPLE_PTR_INDEX (MINIMR_RR_TYPE_A_DEFAULT + MINIMR_RR_TYPE_AAAA_DEFAULT + MINIMR_RR_TYPE_SRV_DEFAULT + MINIMR_RR_TYPE_TXT_DEFAULT)
#endif

extern struct minimr_rr * minimr_simple_rr_set[MINIMR_RR_TYPE_DEFAULT_COUNT];

void minimr_simple_set_ips(uint8_t * ipv4, uint16_t * ipv6);


/************* Simple State Machine ******************/

typedef enum {
    simple_state_init,
    simple_state_probe,
    simple_state_await_probe_response,
    simple_state_announce,
    simple_state_responding,
    simple_state_stopped
} simple_state_t;

simple_state_t minimr_simple_get_state();

struct minimr_simple_init_st {

    /**
     * Called by FSM, when minimr_simple_fsm() should be called to drive internal state processing.
     * Optional. If not given you are expected to call minimr_siple_fsm() regularly.
     */
    void (*processing_required)();

    /**
     * If false (no probing) the records are assumed to be unique. There will be no probing phase.
     * If true (probing) probing_end_timer, restart_in_1sec and reconfiguration_needed are required.
     */
    uint8_t probe_or_not;

    /**
     * called when minimr_simple_reprobe_callback() is to be called
     */
    void (*probing_end_timer)(uint16_t msec);

    /**
     * Notification to host that there is a name conflict and reconfiguration is needed.
     * After reconfiguration by host, a call to minimr_simple_start() is required; the fsm will not process any
     * incoming messages.
     */
    void (*reconfiguration_needed)();

    /**
     * Number of desired announcements
     * May be 0-8.
     *
     * If 0 there will be no announcement...
     * If >1 announcement_timer must be set
     *
     */
    uint8_t announcement_count;

    /**
     * Host is requested to call minimr_simple_announce(..) in given number of seconds
     */
    void (*announcement_timer)(uint16_t sec); // called when an announcement in <sec> seconds is requested


#if MINIMR_TIMESTAMP_USE
    void (*time_now)(MINIMR_TIMESTAMP_TYPE* dst);
    void (*time_cpy)(MINIMR_TIMESTAMP_TYPE* dst, MINIMR_TIMESTAMP_TYPE* src);
    int (*time_diff_sec)(MINIMR_TIMESTAMP_TYPE* before, MINIMR_TIMESTAMP_TYPE* after);
#endif //MINIMR_TIMESTAMP_USE
};

/**
 * Initialize FSM
 * FSM will be in initialization state and will not process any input until minimr_simple_start() is called.
 */
void minimr_simple_init(struct minimr_simple_init_st * init_st);

/**
 * Start FSM
 *
 * IMPORTANT Always call with a random (startup) delay uniformly distributed between 0 - 250 ms. (see https://tools.ietf.org/html/rfc6762#section-8.1 )
 */
void minimr_simple_start();

/**
 * To be called by host when the probing end timer has been triggered.
 */
void minimr_simple_probing_end_timer_callback(uint8_t * outmsg, uint16_t * outmsglen, uint16_t outmsgmaxlen);

/**
 * To be called by host when the announcement timer has been triggered.
 */
int32_t minimr_simple_announce(uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen);

/**
 * Can be called arbitrarily by host to stop FSM and to (optionally) generate a RR invalidation message.
 * If outmsg == NULL || outmsgmaxlen == 0 no message is generated (other hosts might assume that the host is still valid)
 */
int32_t minimr_simple_stop(uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen);


/**
 * Core of FSM to be called either when inbound mDNS messages arrive (passed as msg, msglen) or when a state change occurs.
 * Can also be called in an infinite loop.
 */
int32_t minimr_simple_fsm(uint8_t *msg, uint16_t msglen, uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen, uint8_t *unicast_requested);


/************* Standalone functions (also called by FSM) ******************/
// if you don't want to use the above state machine, you can also use them directly

int32_t minimr_simple_probequery_msg(
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
        uint8_t request_unicast
);

int32_t minimr_simple_announce_msg(
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen
);

int32_t minimr_simple_terminate_msg(
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen
);

int32_t minimr_simple_query_response_msg(
        uint8_t *msg, uint16_t msglen,
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
        uint8_t *unicast_requested
);



#ifdef __cplusplus
}
#endif

#endif //MINIMR_SIMPLE_INTERFACE_ENABLED == 1
#endif //MINIMR_MINIMRSIMPLE_H
