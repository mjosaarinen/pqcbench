#ifndef crypto_kem_H
#define crypto_kem_H

#include "crypto_kem_pqrsa30.h"

//#define crypto_kem_keypair crypto_kem_pqrsa30_keypair
//#define crypto_kem_enc crypto_kem_pqrsa30_enc
//#define crypto_kem_dec crypto_kem_pqrsa30_dec
#define crypto_kem_PUBLICKEYBYTES crypto_kem_pqrsa30_PUBLICKEYBYTES
#define crypto_kem_SECRETKEYBYTES crypto_kem_pqrsa30_SECRETKEYBYTES
#define crypto_kem_BYTES crypto_kem_pqrsa30_BYTES
#define crypto_kem_CIPHERTEXTBYTES crypto_kem_pqrsa30_CIPHERTEXTBYTES
#define crypto_kem_PRIMITIVE "pqrsa30"

#endif
