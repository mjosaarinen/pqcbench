#ifndef crypto_kem_pqrsa25_H
#define crypto_kem_pqrsa25_H

#define crypto_kem_pqrsa25_ref_SECRETKEYBYTES 100663296LL
#define crypto_kem_pqrsa25_ref_PUBLICKEYBYTES 33554432LL
#define crypto_kem_pqrsa25_ref_CIPHERTEXTBYTES 33554432LL
#define crypto_kem_pqrsa25_ref_BYTES 32
 
#ifdef __cplusplus
extern "C" {
#endif
extern int crypto_kem_pqrsa25_ref_keypair(unsigned char *,unsigned char *);
extern int crypto_kem_pqrsa25_ref_enc(unsigned char *,unsigned char *,const unsigned char *);
extern int crypto_kem_pqrsa25_ref_dec(unsigned char *,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_kem_pqrsa25_keypair crypto_kem_pqrsa25_ref_keypair
#define crypto_kem_pqrsa25_enc crypto_kem_pqrsa25_ref_enc
#define crypto_kem_pqrsa25_dec crypto_kem_pqrsa25_ref_dec
#define crypto_kem_pqrsa25_PUBLICKEYBYTES crypto_kem_pqrsa25_ref_PUBLICKEYBYTES
#define crypto_kem_pqrsa25_SECRETKEYBYTES crypto_kem_pqrsa25_ref_SECRETKEYBYTES
#define crypto_kem_pqrsa25_BYTES crypto_kem_pqrsa25_ref_BYTES
#define crypto_kem_pqrsa25_CIPHERTEXTBYTES crypto_kem_pqrsa25_ref_CIPHERTEXTBYTES

#endif
