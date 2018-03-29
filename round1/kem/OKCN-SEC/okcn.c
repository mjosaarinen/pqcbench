
#include "okcn.h"
#include "parameter.h"
#include "reduce.h" 

// It computes [key, signal] <- Con(x; error)
// For the definition of Con(), see Algorithm 1 in the document. 
void OKCN_Con(
	unsigned int * key, 
	unsigned int * signal, 
	const unsigned int x,
	const unsigned int error)
{
	unsigned int temp = Mod2Q(2*ModQ(x)+error);
	
	*key = 0;
	if(temp>=RLWE_Q)
	{
		*key = 1;
		temp -= RLWE_Q;
	}
	
	*signal = (temp<<LOG2G)/RLWE_Q;
}


// It computes key <- Rec(y,signal), and returns key.
// For the definition of Rec(), see Algorithm 1 in the document. 
unsigned int OKCN_Rec(const unsigned int y, const unsigned int signal)
{
	unsigned int temp = (ModQ(y)<<4) + RLWE_Q*(19-(signal<<1));
	
	while(temp >= 16*RLWE_Q)
		temp -= 16*RLWE_Q;
	
	if(temp >= 8*RLWE_Q)
		return 1;
	return 0;
}



