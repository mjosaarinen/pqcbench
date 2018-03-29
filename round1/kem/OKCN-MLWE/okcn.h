#ifndef OKCN_H
#define OKCN_H

void OKCN_Con(
		unsigned int *key, 
		unsigned int *signal, 
		const unsigned int x, 
		const unsigned char error);
		
unsigned int OKCN_Rec(const unsigned int y, const unsigned int signal);


#endif