//
// Created by Philip Tschiemer on 26.06.20.
//

#ifndef MINIMR_MINIMROPT_H
#define MINIMR_MINIMROPT_H

// the standard int definitions (uint8_t etc) are required, define as you please
#include <stdint.h>

#include <stdio.h>
#include <assert.h>

#define MINIMR_ASSERT(x) assert(x)

#define MINIMR_DEBUGF(...) fprintf(stderr, __VA_ARGS__)


// if > 0 will typedef minimr_dns_rr_a with given (max) namelen
#define MINIMR_DNS_RR_TYPE_A_DEFAULT_NAMELEN        0

// if > 0 will typedef minimr_dns_rr_aaaa with given (max) namelen
#define MINIMR_DNS_RR_TYPE_AAAA_DEFAULT_NAMELEN     0

// if > 0 will typedef minimr_dns_rr_ptr with given (max) namelen and domainlen
#define MINIMR_DNS_RR_TYPE_PTR_DEFAULT_NAMELEN      0
#define MINIMR_DNS_RR_TYPE_PTR_DEFAULT_DOMAINLEN    0

// if > 0 will typedef minimr_dns_rr_srv with given (max) namelen and targetlen
#define MINIMR_DNS_RR_TYPE_SRV_DEFAULT_NAMELEN      0
#define MINIMR_DNS_RR_TYPE_SRV_DEFAULT_TARGETLEN    0

// if > 0 will typedef minimr_dns_rr_srv with given (max) namelen and txtlen
#define MINIMR_DNS_RR_TYPE_TXT_DEFAULT_NAMELEN      0
#define MINIMR_DNS_RR_TYPE_TXT_DEFAULT_TXTTLEN      0

#endif //MINIMR_MINIMROPT_H
