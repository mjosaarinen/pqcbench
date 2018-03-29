/******************************************************************************
 * BIKE -- Bit Flipping Key Encapsulation
 *
 * Copyright (c) 2017 Nir Drucker, Shay Gueron, Rafael Misoczki, Tobias Oder, Tim Gueneysu
 * (drucker.nir@gmail.com, shay.gueron@gmail.com, rafael.misoczki@intel.com, tobias.oder@rub.de, tim.gueneysu@rub.de)
 *
 * Permission to use this code for BIKE is granted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * * The names of the contributors may not be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS CORPORATION OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/


#ifndef MEASURE_H
#define MEASURE_H

#ifndef RDTSC
//Less accurate measurement than with RDTSC
#include <time.h>
clock_t start;
clock_t end;

#define MEASURE(msg, x) start = clock(); {x}; end = clock(); \
        printf(msg); \
        printf("\ttook %lfs\n", ((double) (end-start)/CLOCKS_PER_SEC));
#endif

/* This part defines the functions and MACROS needed to measure using RDTSC */
#ifdef RDTSC

#ifndef REPEAT
#define REPEAT 100
#endif

#ifndef OUTER_REPEAT
#define OUTER_REPEAT 1
#endif

#ifndef WARMUP
#define WARMUP REPEAT/4
#endif

unsigned long long RDTSC_start_clk, RDTSC_end_clk;
double RDTSC_total_clk;
double RDTSC_TEMP_CLK;
int RDTSC_MEASURE_ITERATOR;
int RDTSC_OUTER_ITERATOR;

inline static uint64_t get_Clks(void)
{
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtscp\n\t" : "=a"(lo), "=d"(hi)::"rcx");
    return ( (uint64_t)lo)^( ((uint64_t)hi)<<32 );
}

/*
   This MACRO measures the number of cycles "x" runs. This is the flow:
      1) it sets the priority to FIFO, to avoid time slicing if possible.
      2) it repeats "x" WARMUP times, in order to warm the cache.
      3) it reads the Time Stamp Counter at the beginning of the test.
      4) it repeats "x" REPEAT number of times.
      5) it reads the Time Stamp Counter again at the end of the test
      6) it calculates the average number of cycles per one iteration of "x", by calculating the total number of cycles, and dividing it by REPEAT
 */
#define RDTSC_MEASURE(msg, x)                                                                    \
        for(RDTSC_MEASURE_ITERATOR=0; RDTSC_MEASURE_ITERATOR< WARMUP; RDTSC_MEASURE_ITERATOR++)          \
        {                                                                                             \
            {x};                                                                                       \
        }                                                                                                \
        RDTSC_total_clk = 1.7976931348623157e+308;                                                      \
        for(RDTSC_OUTER_ITERATOR=0;RDTSC_OUTER_ITERATOR<OUTER_REPEAT; RDTSC_OUTER_ITERATOR++){          \
            RDTSC_start_clk = get_Clks();                                                                 \
            for (RDTSC_MEASURE_ITERATOR = 0; RDTSC_MEASURE_ITERATOR < REPEAT; RDTSC_MEASURE_ITERATOR++)   \
            {                                                                                             \
                {x};                                                                                       \
            }                                                                                             \
            RDTSC_end_clk = get_Clks();                                                                   \
            RDTSC_TEMP_CLK = (double)(RDTSC_end_clk-RDTSC_start_clk)/REPEAT;                              \
            if(RDTSC_total_clk>RDTSC_TEMP_CLK) RDTSC_total_clk = RDTSC_TEMP_CLK;                        \
        } \
        printf(msg); \
        printf(" took %012.2f cycles in average (%d repetitions)\n", RDTSC_total_clk, REPEAT );


#ifndef COHO
#define MEASURE(msg, x) RDTSC_MEASURE(msg, x)
#endif

#endif

#endif
