
#include "parameter.h"

/* 
	It computes the product of x*y, and then performs the REDC operation. 
	In this implementation, we have n = 1024, q = 12289, R = 2^15, making R' = 4608.
*/
unsigned int REDC(unsigned int x, unsigned int y)
{
	unsigned int value = x*y;

	unsigned int temp = value & ((1<<LOG2R_IN_REDC)-1);

	temp = (temp*QPRIME_IN_REDC) & ((1<<LOG2R_IN_REDC)-1);
	temp = (value + temp*RLWE_Q) >> LOG2R_IN_REDC;

	return ModQ(temp);
}