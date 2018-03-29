#ifndef api_h 
#define api_h

#define SECURITYLVL 256

#if (SECURITYLVL==256)
 #define CRYPTO_ALGNAME "Mersenne756839" 
 #define CRYPTO_BASIC_SECRETKEYBYTES 94624
 #define CRYPTO_SECRETKEYBYTES (SECURITYLVL/8)
 #define CRYPTO_PUBLICKEYBYTES (2*CRYPTO_BASIC_SECRETKEYBYTES)
 #define CRYPTO_BYTES (SECURITYLVL/8)
 #define CRYPTO_RepetitionLength 2048
 #define CRYPTO_CIPHERTEXTBYTES_EXTRA (CRYPTO_BYTES*CRYPTO_RepetitionLength)
 #define CRYPTO_CIPHERTEXTBYTES (CRYPTO_BASIC_SECRETKEYBYTES+CRYPTO_CIPHERTEXTBYTES_EXTRA)
#endif


int crypto_kem_keypair(unsigned char *pk,
		       unsigned char *sk);

int crypto_kem_enc(unsigned char *ct,
		   unsigned char *ss,
		   const unsigned char *pk);

int crypto_kem_dec(unsigned char *ss,
		   const unsigned char *ct,
		   const unsigned char *sk);

#endif /* api_h */
