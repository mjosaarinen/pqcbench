
#include "akcn.h"
#include "parameter.h"
#include "reduce.h"

// It computes signal <- Con(x, key)
// For the full detail, see Algorithm 4 in the document 
unsigned int AKCN_Con(const unsigned int x, unsigned int key)
{
	unsigned int temp = ModQ(x); 
	
	temp += ((key*MLWE_Q + 1)>>1);
	temp = (temp<<5) + (MLWE_Q - 1)/2;
	temp = Barrett_divide(temp, 0);
	
	return (temp & 0x1F);	
}


// It computes key <- Rec(y, signal).
// For the full detail, see Algorithm 4 in the document
unsigned int AKCN_Rec(const unsigned int y, unsigned int signal)
{
	int temp = ModQ(y);
	
	temp = (8*MLWE_Q + MLWE_Q*signal - (temp<<5));

	if(temp<0)
		temp += 32*MLWE_Q;
	else if(temp >= 32*MLWE_Q)
			temp -= 32*MLWE_Q;
		
	return (temp>=16*MLWE_Q);
}


