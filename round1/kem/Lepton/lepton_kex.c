#include "lepton_kex.h"
#include "fips202.h"

/*
Function: Lepton.CPA.KeyGen() with a given random seed
Inputs  : a random seed
Outputs : a pair of public and secret keys (pk,sk)
*/
int lepton_kex_keygen_KAT(uint8_t *pk, uint8_t *sk,const uint8_t *seed)
{
	return lepton_ow_keygen_KAT(pk,sk,seed);//do the core LPN key generation
}

/*
Function: Lepton.CPA.Encaps(pk) with a given random seed
Inputs  : a public key pk and a random seed
Outputs : a ciphertext ct and an encapsulated session key ss
*/
int lepton_kex_enc_KAT(uint8_t *ct, uint8_t *ss, const uint8_t *pk,const uint8_t *seed)
{
	uint8_t buf[CPA_BUF_BYTES];
	int flag;
	
	memcpy(buf,seed,SEED_BYTES);
	memcpy(&buf[SEED_BYTES],pk,CPA_PK_BYTES);
	
	shake128(buf,2*SEED_BYTES,buf,SEED_BYTES + CPA_PK_BYTES);//(m,r)=G(eta||pk,2)
	
	flag = lepton_ow_enc_KAT(ct,pk,buf,&buf[SEED_BYTES]);//do the core LPN encryption
	
	memcpy(&buf[SEED_BYTES],ct,CPA_CT_BYTES);
	shake128(ss,SEED_BYTES,buf,SEED_BYTES + CPA_CT_BYTES);//K = G(m||C)
	return flag;
}

/*
Function: Lepton.CPA.KeyGen()
Inputs  : 
Outputs : a pair of public and secret keys (pk,sk)
*/
int lepton_kex_keygen(uint8_t *pk, uint8_t *sk)
{
	uint8_t seed[SEED_BYTES];
	randombytes(seed,SEED_BYTES);
	return lepton_kex_keygen_KAT(pk,sk,seed);
}

/*
Function: Lepton.CPA.Encaps(pk)
Inputs  : a public key
Outputs : a ciphertext ct and an encapsulated session key ss
*/
int lepton_kex_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
	uint8_t seed[SEED_BYTES];
	randombytes(seed,SEED_BYTES);
	return lepton_kex_enc_KAT(ct,ss,pk,seed);
}

/*
Function: Lepton.CPA.Decaps(sk,C)
Inputs  : a secret key sk and a ciphertext ct 
Outputs : an encapsulated session key ss
*/
int lepton_kex_dec(uint8_t *ss, const uint8_t *sk, const uint8_t *ct)
{
	uint8_t buf[CPA_BUF_BYTES];
	if(lepton_ow_dec_KAT(buf,sk,ct))//do the core LPN decryption
		return -1;
	
	memcpy(&buf[SEED_BYTES],ct,CPA_CT_BYTES);
	shake128(ss,SEED_BYTES,buf,SEED_BYTES+CPA_CT_BYTES);//K = G(m'||C)
	return 0;
}
