/*
 * packing.c
 *
 *  Created on: Aug 30, 2017
 *      Author: zhenfei
 */

#include <stdint.h>
#include "param.h"

/* convert a ring element into a char str */
void
pack_ring_element(
    unsigned char   *str,
    const PARAM_SET *param,
    const int64_t   *ring)
{
    uint16_t    i;
    int32_t     *ptr;

    str[0]  = (unsigned char) param->id;
    ptr     = (int32_t*) (str+1);
    for (i=0;i<param->N;i++)
    {
        ptr[i] = (int32_t) (ring[i]&0xFFFFFFFF);
    }
}


/* convert a char str into a ring element */
void
unpack_ring_element(
    const unsigned char
                    *str,
    PARAM_SET       *param,
    int64_t         *ring)
{
    uint16_t    i;
    int32_t     *ptr;

    param   = get_param_set_by_id(str[0]);

    ptr     = (int32_t*) (str+1);
    for (i=0;i<param->N;i++)
    {
        ring[i] =  ptr[i];
    }
}
