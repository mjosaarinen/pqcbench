/*
 * param.c
 *
 *  Created on: Aug 16, 2017
 *      Author: zhenfei
 */


#include <string.h>
#include "param.h"

static PARAM_SET ParamSets[] = {
    {
      NTRU_KEM_1024,        /* parameter set id */
      "NTRU_KEM_1024",      /* human readable name */
      {0xff, 0xff, 0xf9},   /* OID */
      11,                   /* bitlength of N */
      32,                   /* bitlength of q */
      1024,                 /* ring degree */
      2,                    /* message space prime */
      1073750017,           /* ring modulus, 2^30+2^13+1 */
      724,                  /* standard deviation,  */
      95,                  /* maximum message length (in bytes) */
    },
    {
      NTRU_CCA_1024,        /* parameter set id */
      "NTRU_PKE_1024",      /* human readable name */
      {0xff, 0xff, 0xf9},   /* OID */
      11,                   /* bitlength of N */
      32,                   /* bitlength of q */
      1024,                 /* ring degree */
      2,                    /* message space prime */
      1073750017,           /* ring modulus, 2^30+2^13+1 */
      724,                  /* standard deviation,  */
      95,                   /* maximum message length in bytes*/
    },
};

static int numParamSets = sizeof(ParamSets)/sizeof(PARAM_SET);

PARAM_SET *
get_param_set_by_id(PARAM_SET_ID id)
{
  int i;

  for(i=0; i<numParamSets; i++)
  {
    if(ParamSets[i].id == id)
    {
      return (ParamSets + i);
    }
  }
  return NULL;
}
