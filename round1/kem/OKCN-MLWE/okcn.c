
#include "okcn.h"
#include "parameter.h"
#include "reduce.h"

// It computes [key, signal] <- Con(x; error)
// For the definition of Con(), see Algorithm 1 in the document. 
void OKCN_Con(
		unsigned int *key, 
		unsigned int *signal, 
		const unsigned int x, 
		const unsigned char error)
{
	unsigned int temp = ModQ(x);
	temp = (temp<<1) + error;
	temp = Barrett_reduce(temp, 1);

	*key = 0;
	if(temp >= MLWE_Q)
	{
		*key = 1;
		temp -= MLWE_Q;
	}

	*signal = Barrett_divide(temp<<5, 0);
}

// It computes key <- Rec(y,signal), and returns key.
// For the definition of Rec(), see Algorithm 1 in the document. 
unsigned int OKCN_Rec(const unsigned int y, const unsigned int signal)
{	
	unsigned int temp = ModQ(y);	
	temp = (temp<<7) + (159- (signal<<1)) * MLWE_BETA;
	return Barrett_divide(temp, 6);
}

