//
// Created by Philip Tschiemer on 26.06.20.
//

#ifndef MINIMR_MINIMROPT_H
#define MINIMR_MINIMROPT_H

// application specific includes
#include <stdio.h>
#include <assert.h>


// the standard int definitions (uint8_t etc) are required, define as you please
#include <stdint.h>


// optional
#define MINIMR_ASSERT(x) assert(x)

// optional
#define MINIMR_DEBUGF(...) fprintf(stderr, __VA_ARGS__)


#endif //MINIMR_MINIMROPT_H
