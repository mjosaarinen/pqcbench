
#include "akcn.h"
#include "parameter.h"
#include "reduce.h"

// It computes signal <- Con(x, key)
// For the full detail, see Algorithm 4 in the document 
unsigned int AKCN_Con(unsigned int x, unsigned int key)
{
	unsigned int temp = (key*RLWE_Q+1)/2 + ModQ(x);

	for(temp = ((temp<<3)+(RLWE_Q-1)/2); temp>=8*RLWE_Q; temp-=8*RLWE_Q);

	return (temp/RLWE_Q);
}

// It computes key <- Rec(y, signal).
// For the full detail, see Algorithm 4 in the document
unsigned int AKCN_Rec(unsigned int y, unsigned int signal)
{
	unsigned int temp = (signal+10)*RLWE_Q - 8*ModQ(y);

	while(temp>=8*RLWE_Q)
		temp -= 8*RLWE_Q;

	return (temp >= 4*RLWE_Q);
}



