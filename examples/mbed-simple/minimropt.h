/**
 * minimr - mini mDNS Responder (framework)
 *
 * https://github.com/tschiemer/minimr
 *
 * MIT License
 *
 * Copyright (c) 2020 Philip Tschiemer, filou.se
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
