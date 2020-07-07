//
// Created by Philip Tschiemer on 26.06.20.
//

#ifndef MINIMR_MINIMROPT_H
#define MINIMR_MINIMROPT_H

// the standard int definitions (uint8_t etc) are required, define as you please
#include <stdint.h>

// #define MINIMR_DEBUGF(...) printf(__VA_ARGS__);

#define MINIMR_SIMPLE_INTERFACE_ENABLED 1

#define MINIMR_SIMPLE_HOSTNAME          ".here-be-kittens.local"
#define MINIMR_SIMPLE_SERVICE_PTR       "._echo._udp.local"
#define MINIMR_SIMPLE_SERVICE_NAME      ".Here be Kittens._echo._udp.local"
#define MINIMR_SIMPLE_SERVICE_WEIGHT    0
#define MINIMR_SIMPLE_SERVICE_PRIORITY  0
#define MINIMR_SIMPLE_SERVICE_PORT      7
#define MINIMR_SIMPLE_SERVICE_TXTMARKER '/'
#define MINIMR_SIMPLE_SERVICE_TXT       "/key1=value1/key2=value2"


#define MINIMR_RR_TYPE_A_DEFAULT_NAMELEN        256
#define MINIMR_RR_TYPE_AAAA_DEFAULT_NAMELEN     256
#define MINIMR_RR_TYPE_PTR_DEFAULT_NAMELEN      256
#define MINIMR_RR_TYPE_PTR_DEFAULT_DOMAINLEN    256
#define MINIMR_RR_TYPE_SRV_DEFAULT_NAMELEN      256
#define MINIMR_RR_TYPE_SRV_DEFAULT_TARGETLEN    256
#define MINIMR_RR_TYPE_TXT_DEFAULT_NAMELEN      256
#define MINIMR_RR_TYPE_TXT_DEFAULT_TXTLEN       256


#endif //MINIMR_MINIMROPT_H
