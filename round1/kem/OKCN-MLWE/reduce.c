
#include "parameter.h"

// It computes (x*R' mod q) according to REDC algorithm.
// In this implementation, q = 7681, R = 2^18, making R' = 225.
unsigned int REDC(const unsigned int x)
{
	unsigned int temp;
	temp = ((x & ((1<<LOG2R_IN_REDC)-1)) * QPRIME_IN_REDC) & ((1<<LOG2R_IN_REDC)-1);

	return ((x+temp*MLWE_Q) >> LOG2R_IN_REDC);
}

// It computes x mod (2^exponent*q), as the name suggests. 
// By default, exponent = 0, and it computes (x mod q)
// In this implementation, we have q = 7681, k = 18. 
unsigned int Barrett_reduce(
	const unsigned int x, 
	unsigned int exponent)
{	
	unsigned int temp;

	temp = (x*M_IN_BARRETT_REDUCE) >> (exponent+K_IN_BARRETT_REDUCE);
	temp = x - temp*MLWE_Q;
	
	if(temp >= (1<<exponent)*MLWE_Q)
		temp -= (1<<exponent)*MLWE_Q;

	return temp;
}


// It computes x/(q*2^exponent) according to the Barrett algorithm.
// In this implementation, we have q = 7681, k = 18. 
unsigned int Barrett_divide(const unsigned int x, unsigned int exponent)
{	
	unsigned int result = (x*M_IN_BARRETT_REDUCE) >> (exponent+K_IN_BARRETT_REDUCE);
	unsigned int temp = x - result*MLWE_Q*(1<<exponent);
	
	if(temp >= (1<<exponent)*MLWE_Q)
		result++;

	return result;
}
 