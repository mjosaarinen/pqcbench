/* kem.c
 * https://bench.cr.yp.to/call-encrypt.html 
 * http://csrc.nist.gov/groups/ST/post-quantum-crypto/documents/example-files/api-notes.pdf
 */
#include "api.h"
#include "rlce.h"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
  unsigned int para[PARASIZE];
  int ret;
  ret=getRLCEparameters(para,CRYPTO_SCHEME,CRYPTO_PADDING);
  if (ret<0) return ret;
  unsigned char randomness[para[19]];
  randombytes(randomness, para[19]);

  RLCE_private_key_t RLCEsk=RLCE_private_key_init(para);
  RLCE_public_key_t RLCEpk=RLCE_public_key_init(para);
  unsigned char nonce[]={0x5e,0x7d,0x69,0xe1,0x87,0x57,0x7b,0x04,0x33,0xee,0xe8,0xea,0xb9,0xf7,0x77,0x31};
  ret=RLCE_key_setup((unsigned char *)randomness,para[19], nonce, 16, RLCEpk, RLCEsk);
  if (ret<0) return ret;
  unsigned int sklen=CRYPTO_SECRETKEYBYTES;
  unsigned int pklen=CRYPTO_PUBLICKEYBYTES;
  ret=pk2B(RLCEpk,pk,&pklen);
  ret=sk2B(RLCEsk,sk,&sklen);
  return ret;
}

int crypto_kem_enc(unsigned char *ct,unsigned char *ss,const unsigned char *pk) {
  int ret;
  RLCE_public_key_t RLCEpk=B2pk(pk, CRYPTO_PUBLICKEYBYTES);
  if (RLCEpk==NULL) return -1;
  unsigned long long RLCEmlen=RLCEpk->para[6];
  unsigned char randomness[RLCEpk->para[19]];
  randombytes(randomness, RLCEpk->para[19]);
  unsigned char *message=calloc(RLCEmlen, sizeof(unsigned char)); 
  memcpy(message, ss, CRYPTO_BYTES);
  unsigned long long ctlen=CRYPTO_CIPHERTEXTBYTES;
  unsigned char nonce[1];
  ret=RLCE_encrypt(message,RLCEmlen,(unsigned char *)randomness,RLCEpk->para[19],nonce,0,RLCEpk,ct,&ctlen);
  free(message);
  return ret;
}

int crypto_kem_dec(unsigned char *ss,const unsigned char *ct,const unsigned char *sk) {
  int ret;
  RLCE_private_key_t RLCEsk=B2sk(sk, CRYPTO_SECRETKEYBYTES);
  if (RLCEsk==NULL) return -1;
  unsigned char message[RLCEsk->para[6]];
  unsigned long long mlen=RLCEsk->para[6];
  ret=RLCE_decrypt((unsigned char *)ct,CRYPTO_CIPHERTEXTBYTES,RLCEsk,message,&mlen);
  if (ret<0) return ret;
  memcpy(ss, message, CRYPTO_BYTES);
  return ret;
}
  
