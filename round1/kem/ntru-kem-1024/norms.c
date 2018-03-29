/*
 *  Copyright 2017 Zhenfei Zhang @ onboard security
 *
 *  This file is part of pqNTRUSign signature scheme with bimodal
 *  Gaussian sampler (Gaussian-pqNTRUSign).
 *
 *  This software is released under GPL:
 *  you can redistribute it and/or modify it under the terms of the
 *  GNU General Public License as published by the Free Software
 *  Foundation, either version 2 of the License, or (at your option)
 *  any later version.
 *
 *  You should have received a copy of the GNU General Public License.
 *  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdint.h>
#include <stdlib.h>
int64_t max_norm(const int64_t *f, const int16_t N)
{
    int16_t i;
    int64_t norm = 0;

    for (i=0;i<N;i++)
    {
        if (abs(f[i])>norm)
            norm = abs(f[i]);
    }
    return norm;
}

/* return the square of the l2 norm */
int64_t l2_norm(const int64_t *f, const int16_t N)
{
    int16_t i;
    int64_t norm = 0;

    for (i=0;i<N;i++)
    {
        norm += f[i]*f[i];
    }
    return norm;
}


/* return the scala product of two vectors */
int64_t get_scala(
        const int64_t *f,
        const int64_t *g,
        const int16_t N)
{
    int16_t i;
    int64_t product = 0;
    for (i=0;i<N;i++)
        product += f[i]*g[i];
    return product;
}
