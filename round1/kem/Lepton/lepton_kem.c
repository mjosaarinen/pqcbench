#include "lepton_kem.h"
#include "fips202.h"


/*
Function: Lepton.CCA.KeyGen() with a given random seed
Inputs  : a random seed
Outputs : a pair of public and secret keys (pk,sk)
*/
int lepton_kem_keygen_KAT(uint8_t *pk, uint8_t *sk,const uint8_t *seed)
{
	int flag;
	flag = lepton_ow_keygen_KAT(pk,&sk[CPA_PK_BYTES],seed);//do the core LPN key generation
	memcpy(sk,pk,CCA_PK_BYTES);//set the public-key as part of the secret for decryption.
  return flag;
}

/*
Function: Lepton.CCA.Encaps(pk) with a given random seed
Inputs  : a public key pk and a random seed
Outputs : a ciphertext ct and an encapsulated session key ss
*/
int lepton_kem_enc_KAT(uint8_t *ct, uint8_t *ss, const uint8_t *pk,const uint8_t *seed)
{
	uint8_t buf[CCA_BUF_BYTES];
	int flag;
	memcpy(buf,seed,SEED_BYTES);
	memcpy(&buf[SEED_BYTES],pk,CCA_PK_BYTES);
	shake128(buf,3*SEED_BYTES,buf,SEED_BYTES + CCA_PK_BYTES);//(K',r,d) = G(m||pk,3)
	flag = lepton_ow_enc_KAT(ct,pk,seed,&buf[SEED_BYTES]);//do the core LPN encryption
	memcpy(&ct[CPA_CT_BYTES],&buf[2*SEED_BYTES],SEED_BYTES);
	memcpy(&buf[SEED_BYTES],ct,CCA_CT_BYTES);
	shake128(ss,SEED_BYTES,buf,SEED_BYTES + CCA_CT_BYTES);//K = G(K'||C)
    
  return flag;
}

/*
Function: Lepton.CCA.KeyGen()
Inputs  : 
Outputs : a pair of pubic and secret keys (pk,sk)
*/
int lepton_kem_keygen(uint8_t *pk, uint8_t *sk)
{
	uint8_t seed[SEED_BYTES];
	randombytes(seed,SEED_BYTES);
	return lepton_kem_keygen_KAT(pk,sk,seed);
	
}

/*
Function: Lepton.CCA.Encaps(pk)
Inputs  : a public key
Outputs : a ciphertext ct and an encapsulated session key ss
*/
int lepton_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
	uint8_t seed[SEED_BYTES];
	randombytes(seed,SEED_BYTES);
	return lepton_kem_enc_KAT(ct,ss,pk,seed);
}

/*
Function: Lepton.CCA.Decaps(sk,C)
Inputs  : a secret key sk and a ciphertext ct 
Outputs : an encapsulated session key ss
*/
int lepton_kem_dec(uint8_t *ss, const uint8_t *sk, const uint8_t *ct)
{
	uint8_t cct[CCA_CT_BYTES],msg[SEED_BYTES];
	int flag=0;
	
	flag = lepton_ow_dec_KAT(msg,&sk[CCA_PK_BYTES],ct);//do the core LPN decryption
	flag |= lepton_kem_enc_KAT(cct,msg,sk,msg);//re-do the encapulation for checking

	if(memcmp(cct,ct,CCA_CT_BYTES)!=0)
	{
		memset(ss,0,SEED_BYTES);
		flag =-1;
	}
	else
		memcpy(ss,msg,SEED_BYTES);
	return flag;
}


