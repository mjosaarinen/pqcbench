#ifndef crypto_kem_pqrsa15_H
#define crypto_kem_pqrsa15_H

#define crypto_kem_pqrsa15_ref_SECRETKEYBYTES 98304
#define crypto_kem_pqrsa15_ref_PUBLICKEYBYTES 32768
#define crypto_kem_pqrsa15_ref_CIPHERTEXTBYTES 32768
#define crypto_kem_pqrsa15_ref_BYTES 32
 
#ifdef __cplusplus
extern "C" {
#endif
extern int crypto_kem_pqrsa15_ref_keypair(unsigned char *,unsigned char *);
extern int crypto_kem_pqrsa15_ref_enc(unsigned char *,unsigned char *,const unsigned char *);
extern int crypto_kem_pqrsa15_ref_dec(unsigned char *,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_kem_pqrsa15_keypair crypto_kem_pqrsa15_ref_keypair
#define crypto_kem_pqrsa15_enc crypto_kem_pqrsa15_ref_enc
#define crypto_kem_pqrsa15_dec crypto_kem_pqrsa15_ref_dec
#define crypto_kem_pqrsa15_PUBLICKEYBYTES crypto_kem_pqrsa15_ref_PUBLICKEYBYTES
#define crypto_kem_pqrsa15_SECRETKEYBYTES crypto_kem_pqrsa15_ref_SECRETKEYBYTES
#define crypto_kem_pqrsa15_BYTES crypto_kem_pqrsa15_ref_BYTES
#define crypto_kem_pqrsa15_CIPHERTEXTBYTES crypto_kem_pqrsa15_ref_CIPHERTEXTBYTES

#endif
