/* sha.c
 * Yongge Wang 
 *
 * Code was written: November 12, 2016-November 26, 2016
 *
 * sha.c implements SHA-1 (SHA-160), SHA256, and SHA512 for RLCE
 *
 * This code is for prototype purpose only and is not optimized
 *
 * Copyright (C) 2016 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 */

#include "rlce.h"

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTR(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define Sigma1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sigma0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

#define ROTL512(a,b) (((a) << (b)) | ((a) >> (64-(b))))
#define ROTR512(a,b) (((a) >> (b)) | ((a) << (64-(b))))
#define sigma5120(x) (ROTR512(x,1) ^ ROTR512(x,8) ^ ((x) >> 7))
#define sigma5121(x) (ROTR512(x,19) ^ ROTR512(x,61) ^ ((x) >> 6))
#define Sigma5120(x) (ROTR512(x,28) ^ ROTR512(x,34) ^ ROTR512(x,39))
#define Sigma5121(x) (ROTR512(x,14) ^ ROTR512(x,18) ^ ROTR512(x,41))

void sha1_process(unsigned int[], unsigned char[]);
void sha256_process(unsigned int[], unsigned char[]);
void sha512_process(unsigned long [], unsigned char []);

void sha_msg_pad(unsigned char message[], int size, unsigned int bitlen,
		 unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<size; i++) {
    paddedmsg[i]=message[i];
  }
  paddedmsg[size]= 0x80;
  for (i=size+1; i<64; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[63] = bitlen;
  paddedmsg[62] = bitlen >> 8;
  paddedmsg[61] = bitlen >> 16;
  paddedmsg[60] = bitlen >> 24;
  return;
}

void sha_msg_pad0(unsigned int bitlen, unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<64; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[63] = bitlen;
  paddedmsg[62] = bitlen >> 8;
  paddedmsg[61] = bitlen >> 16;
  paddedmsg[60] = bitlen >> 24;
  return;
}

void sha1_md(unsigned char message[], int size, unsigned int hash[5]) {
  unsigned int bitlen = 8*size;
  hash[0] = 0x67452301;
  hash[1] = 0xEFCDAB89;
  hash[2] = 0x98BADCFE;
  hash[3] = 0x10325476;
  hash[4] = 0xC3D2E1F0;
  int i;

  unsigned char msgTBH[64]; /* 64 BYTE msg to be hashed */
  unsigned char paddedMessage[64]; /* last msg block to be hashed*/

  int Q= size/64;
  int R= size%64;
  unsigned char msg[R];
  memcpy(msg, &message[64*Q], R * sizeof(unsigned char));
  
  for (i=0; i<Q; i++) {
    memcpy(msgTBH, &message[64*i], 64 * sizeof(unsigned char));
    sha1_process(hash, msgTBH);
  }
  if (R>55) {
    memcpy(msgTBH, msg, R * sizeof(unsigned char));
    msgTBH[R]=0x80;
    for (i=R+1; i<64; i++) {
      msgTBH[i]=0x00;
    } 
    sha1_process(hash, msgTBH);
    sha_msg_pad0(bitlen,paddedMessage);
  } else {
    sha_msg_pad(msg, R, bitlen, paddedMessage);
  }
  sha1_process(hash, paddedMessage);
  return;
}

void sha1_process(unsigned int hash[], unsigned char msg[]) {
  const unsigned int K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
  unsigned int W[80];
  unsigned int A, B, C, D, E, T;
  int i;
  for(i = 0; i < 16; i++) {
    W[i] = (((unsigned) msg[i * 4]) << 24) +
      (((unsigned) msg[i * 4 + 1]) << 16) +
      (((unsigned) msg[i * 4 + 2]) << 8) +
      (((unsigned) msg[i * 4 + 3]));
  }
  for(i = 16; i < 80; i++) {
    W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
    W[i] = ROTL(W[i],1);
  }

  A = hash[0];
  B = hash[1];
  C = hash[2];
  D = hash[3];
  E = hash[4];

  for(i = 0; i < 20; i++) {
    T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[i] + K[0];
    E = D;
    D = C;
    C = ROTL(B, 30);
    B = A;
    A = T;
  }
  for(i = 20; i < 40; i++) {
    T = ROTL(A,5) + (B^C^D) + E + W[i] + K[1];
    E = D;
    D = C;
    C = ROTL(B, 30);
    B = A;
    A = T;
  }
  for(i = 40; i < 60; i++) {
    T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[i] + K[2];
    E = D;
    D = C;
    C = ROTL(B, 30);
    B = A;
    A = T;
  }
  for(i = 60; i < 80; i++) {
    T = ROTL(A,5) + (B ^ C ^ D) + E + W[i] + K[3];
    E = D;
    D = C;
    C = ROTL(B, 30);
    B = A;
    A = T;
    /* printf("%d: %x %x %x %x %x\n",i, A, B, C, D, E); */
  }

  hash[0] +=  A;
  hash[1] +=  B;
  hash[2] +=  C;
  hash[3] +=  D;
  hash[4] +=  E;
  return;
}

void sha256_md(unsigned char message[], int size, unsigned int hash[8]) {
  unsigned int bitlen = 8*size;
  hash[0] = 0x6A09E667;  
  hash[1] = 0xBB67AE85;
  hash[2] = 0x3C6EF372;  
  hash[3] = 0xA54FF53A;  
  hash[4] = 0x510E527F;
  hash[5] = 0x9B05688C;
  hash[6] = 0x1F83D9AB;
  hash[7] = 0x5BE0CD19;
  
  unsigned char msgTBH[64]; /* 64 BYTE msg to be hashed */
  unsigned char paddedMessage[64]; /* last msg block to be hashed*/
  int i;
  int Q= size/64;
  int R= size%64;
  unsigned char msg[R];
  memcpy(msg, &message[64*Q], R * sizeof(unsigned char));
  
  for (i=0; i<Q; i++) {
    memcpy(msgTBH, &message[64*i], 64 * sizeof(unsigned char));
    sha256_process(hash, msgTBH);
  }
  if (R>55) {
    memcpy(msgTBH, msg, R * sizeof(unsigned char));
    msgTBH[R]=0x80;
    for (i=R+1; i<64; i++) {
      msgTBH[i]=0x00;
    }
    sha256_process(hash, msgTBH);
    sha_msg_pad0(bitlen,paddedMessage);
  } else {
    sha_msg_pad(msg, R, bitlen, paddedMessage);
  }
 
  sha256_process(hash, paddedMessage);
  return;
}

void sha256_process(unsigned int hash[], unsigned char msg[]) {
  const unsigned int K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
  unsigned int W[64];
  int i;
  unsigned int A, B, C, D, E, F, G, H, T1, T2;
  for(i = 0; i < 16; i++) {
    W[i] = (((unsigned) msg[i * 4]) << 24) |
      (((unsigned) msg[i * 4 + 1]) << 16) |
      (((unsigned) msg[i * 4 + 2]) << 8) | 
      (((unsigned) msg[i * 4 + 3]));
  }
  for(i = 16; i < 64; i++) {
    W[i] = sigma1(W[i-2])+W[i-7]+sigma0(W[i-15])+ W[i-16];
  }
  A = hash[0];
  B = hash[1];
  C = hash[2];
  D = hash[3];
  E = hash[4];
  F = hash[5];
  G = hash[6];
  H = hash[7];

  for (i = 0; i < 64; ++i) {
    T1 = H + Sigma1(E) + CH(E,F,G) + K[i] + W[i];
    T2 = Sigma0(A) + MAJ(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + T1;
    D = C;
    C = B;
    B = A;
    A = T1 + T2;
  }
  
  hash[0] +=A;
  hash[1] +=B;
  hash[2] +=C;
  hash[3] +=D;
  hash[4] +=E;
  hash[5] +=F;
  hash[6] +=G;
  hash[7] +=H;
  return;
}


void sha512_msg_pad(unsigned char message[], int size, unsigned int bitlen, unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<size; i++) {
    paddedmsg[i]=message[i];
  }
  paddedmsg[size]= 0x80;
  for (i=size+1; i<128; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[127] = bitlen;
  paddedmsg[126] = bitlen >> 8;
  paddedmsg[125] = bitlen >> 16;
  paddedmsg[124] = bitlen >> 24;
  return;
}

void sha512_msg_pad0(unsigned int bitlen, unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<128; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[127] = bitlen;
  paddedmsg[126] = bitlen >> 8;
  paddedmsg[125] = bitlen >> 16;
  paddedmsg[124] = bitlen >> 24;
  return;
}


void sha512_md(unsigned char message[], int size, unsigned long hash[8]) {
  unsigned int bitlen = 8*size;
  hash[0] = 0x6a09e667f3bcc908;
  hash[1] = 0xbb67ae8584caa73b;
  hash[2] = 0x3c6ef372fe94f82b;
  hash[3] = 0xa54ff53a5f1d36f1;
  hash[4] = 0x510e527fade682d1;
  hash[5] = 0x9b05688c2b3e6c1f;
  hash[6] = 0x1f83d9abfb41bd6b;
  hash[7] = 0x5be0cd19137e2179;
  
  unsigned char msgTBH[128]; /* 128 BYTE msg to be hashed */
  unsigned char paddedMessage[128]; /* last msg block to be hashed*/
  
  int Q= size/128;
  int R= size%128;
  unsigned char msg[R];
  memcpy(msg, &message[128*Q], R * sizeof(unsigned char));
  int i;
  for (i=0; i<Q; i++) {
    memcpy(msgTBH, &message[128*i], 128 * sizeof(unsigned char));
    sha512_process(hash, msgTBH);
  }
  if (R>111) {
    memcpy(msgTBH, msg, R * sizeof(unsigned char));
    msgTBH[R]=0x80;
    for (i=R+1; i<128; i++) {
      msgTBH[i]=0x00;
    }
    sha512_process(hash, msgTBH);
    sha512_msg_pad0(bitlen,paddedMessage);
  } else {
    sha512_msg_pad(msg, R, bitlen, paddedMessage);
  }
 
  sha512_process(hash, paddedMessage);
  return;
}



void sha512_process(unsigned long hash[], unsigned char msg[]) {
  const unsigned long K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
  unsigned long W[80];
  unsigned long A, B, C, D, E, F, G, H, T1, T2,X,Y,X1,Y1,X2,Y2, X3,Y3,X4,Y4;

   W[0] = (((unsigned long) msg[0]) << 56) | (((unsigned long) msg[1]) << 48) | (((unsigned long) msg[ 2]) << 40) | 
           (((unsigned long) msg[3]) << 32) | (((unsigned long) msg[4]) << 24) | (((unsigned long) msg[5]) << 16) | 
           (((unsigned long) msg[6]) << 8)  | (((unsigned long) msg[7]));
    W[1] = (((unsigned long) msg[8]) << 56) | (((unsigned long) msg[9]) << 48) | (((unsigned long) msg[10]) << 40) | 
           (((unsigned long) msg[11]) << 32) | (((unsigned long) msg[12]) << 24) | (((unsigned long) msg[13]) << 16) | 
           (((unsigned long) msg[14]) << 8)  | (((unsigned long) msg[15]));
    W[2] = (((unsigned long) msg[16]) << 56) | (((unsigned long) msg[17]) << 48) | (((unsigned long) msg[18]) << 40) | 
           (((unsigned long) msg[19]) << 32) | (((unsigned long) msg[20]) << 24) | (((unsigned long) msg[21]) << 16) | 
           (((unsigned long) msg[22]) << 8)  | (((unsigned long) msg[23]));
    W[3] = (((unsigned long) msg[24]) << 56) | (((unsigned long) msg[25]) << 48) | (((unsigned long) msg[26]) << 40) | 
           (((unsigned long) msg[27]) << 32) | (((unsigned long) msg[28]) << 24) | (((unsigned long) msg[29]) << 16) | 
           (((unsigned long) msg[30]) << 8)  | (((unsigned long) msg[31]));
    W[4] = (((unsigned long) msg[32]) << 56) | (((unsigned long) msg[33]) << 48) | (((unsigned long) msg[34]) << 40) | 
           (((unsigned long) msg[35]) << 32) | (((unsigned long) msg[36]) << 24) | (((unsigned long) msg[37]) << 16) | 
           (((unsigned long) msg[38]) << 8)  | (((unsigned long) msg[39]));
    W[5] = (((unsigned long) msg[40]) << 56) | (((unsigned long) msg[41]) << 48) | (((unsigned long) msg[42]) << 40) | 
           (((unsigned long) msg[43]) << 32) | (((unsigned long) msg[44]) << 24) | (((unsigned long) msg[45]) << 16) | 
           (((unsigned long) msg[46]) << 8)  | (((unsigned long) msg[47]));
    W[6] = (((unsigned long) msg[48]) << 56) | (((unsigned long) msg[49]) << 48) | (((unsigned long) msg[50]) << 40) | 
           (((unsigned long) msg[51]) << 32) | (((unsigned long) msg[52]) << 24) | (((unsigned long) msg[53]) << 16) | 
           (((unsigned long) msg[54]) << 8)  | (((unsigned long) msg[55]));
    W[7] = (((unsigned long) msg[56]) << 56) | (((unsigned long) msg[57]) << 48) | (((unsigned long) msg[58]) << 40) | 
           (((unsigned long) msg[59]) << 32) | (((unsigned long) msg[60]) << 24) | (((unsigned long) msg[61]) << 16) | 
           (((unsigned long) msg[62]) << 8)  | (((unsigned long) msg[63]));
    W[8] = (((unsigned long) msg[64]) << 56) | (((unsigned long) msg[65]) << 48) | (((unsigned long) msg[66]) << 40) | 
           (((unsigned long) msg[67]) << 32) | (((unsigned long) msg[68]) << 24) | (((unsigned long) msg[69]) << 16) | 
           (((unsigned long) msg[70]) << 8)  | (((unsigned long) msg[71]));
    W[9] = (((unsigned long) msg[72]) << 56) | (((unsigned long) msg[73]) << 48) | (((unsigned long) msg[74]) << 40) | 
           (((unsigned long) msg[75]) << 32) | (((unsigned long) msg[76]) << 24) | (((unsigned long) msg[77]) << 16) | 
           (((unsigned long) msg[78]) << 8)  | (((unsigned long) msg[79]));
    W[10] = (((unsigned long) msg[80]) << 56) | (((unsigned long) msg[81]) << 48) | (((unsigned long) msg[82]) << 40) | 
            (((unsigned long) msg[83]) << 32) | (((unsigned long) msg[84]) << 24) | (((unsigned long) msg[85]) << 16) | 
            (((unsigned long) msg[86]) << 8)  | (((unsigned long) msg[87]));
    W[11] = (((unsigned long) msg[88]) << 56) | (((unsigned long) msg[89]) << 48) | (((unsigned long) msg[90]) << 40) | 
            (((unsigned long) msg[91]) << 32) | (((unsigned long) msg[92]) << 24) | (((unsigned long) msg[93]) << 16) | 
            (((unsigned long) msg[94]) << 8)  | (((unsigned long) msg[95]));
    W[12] = (((unsigned long) msg[96]) << 56) | (((unsigned long) msg[97]) << 48) | (((unsigned long) msg[98]) << 40) | 
            (((unsigned long) msg[99]) << 32) | (((unsigned long) msg[100]) << 24) | (((unsigned long) msg[101]) << 16) | 
            (((unsigned long) msg[102]) << 8)  | (((unsigned long) msg[103]));
    W[13] = (((unsigned long) msg[104]) << 56) | (((unsigned long) msg[105]) << 48) | (((unsigned long) msg[106]) << 40) | 
            (((unsigned long) msg[107]) << 32) | (((unsigned long) msg[108]) << 24) | (((unsigned long) msg[109]) << 16) | 
            (((unsigned long) msg[110]) << 8)  | (((unsigned long) msg[111]));
    W[14] = (((unsigned long) msg[112]) << 56) | (((unsigned long) msg[113]) << 48) | (((unsigned long) msg[114]) << 40) | 
            (((unsigned long) msg[115]) << 32) | (((unsigned long) msg[116]) << 24) | (((unsigned long) msg[117]) << 16) | 
            (((unsigned long) msg[118]) << 8)  | (((unsigned long) msg[119]));
    W[15] = (((unsigned long) msg[120]) << 56) | (((unsigned long) msg[121]) << 48) | (((unsigned long) msg[122]) << 40) | 
            (((unsigned long) msg[123]) << 32) | (((unsigned long) msg[124]) << 24) | (((unsigned long) msg[125]) << 16) | 
            (((unsigned long) msg[126]) << 8)  | (((unsigned long) msg[127]));
    
    W[16] = sigma5121(W[14])+W[9]+sigma5120(W[1])+ W[0];
    W[17] = sigma5121(W[15])+W[10]+sigma5120(W[2])+ W[1];
    W[18] = sigma5121(W[16])+W[11]+sigma5120(W[3])+ W[2];
    W[19] = sigma5121(W[17])+W[12]+sigma5120(W[4])+ W[3];
    W[20] = sigma5121(W[18])+W[13]+sigma5120(W[5])+ W[4];
    W[21] = sigma5121(W[19])+W[14]+sigma5120(W[6])+ W[5];
    W[22] = sigma5121(W[20])+W[15]+sigma5120(W[7])+ W[6];
    W[23] = sigma5121(W[21])+W[16]+sigma5120(W[8])+ W[7];
    W[24] = sigma5121(W[22])+W[17]+sigma5120(W[9])+ W[8];
    W[25] = sigma5121(W[23])+W[18]+sigma5120(W[10])+ W[9];
    W[26] = sigma5121(W[24])+W[19]+sigma5120(W[11])+ W[10];
    W[27] = sigma5121(W[25])+W[20]+sigma5120(W[12])+ W[11];
    W[28] = sigma5121(W[26])+W[21]+sigma5120(W[13])+ W[12];
    W[29] = sigma5121(W[27])+W[22]+sigma5120(W[14])+ W[13];
    W[30] = sigma5121(W[28])+W[23]+sigma5120(W[15])+ W[14];
    W[31] = sigma5121(W[29])+W[24]+sigma5120(W[16])+ W[15];
    W[32] = sigma5121(W[30])+W[25]+sigma5120(W[17])+ W[16];
    W[33] = sigma5121(W[31])+W[26]+sigma5120(W[18])+ W[17];
    W[34] = sigma5121(W[32])+W[27]+sigma5120(W[19])+ W[18];
    W[35] = sigma5121(W[33])+W[28]+sigma5120(W[20])+ W[19];
    W[36] = sigma5121(W[34])+W[29]+sigma5120(W[21])+ W[20];
    W[37] = sigma5121(W[35])+W[30]+sigma5120(W[22])+ W[21];
    W[38] = sigma5121(W[36])+W[31]+sigma5120(W[23])+ W[22];
    W[39] = sigma5121(W[37])+W[32]+sigma5120(W[24])+ W[23];
    W[40] = sigma5121(W[38])+W[33]+sigma5120(W[25])+ W[24];
    W[41] = sigma5121(W[39])+W[34]+sigma5120(W[26])+ W[25];
    W[42] = sigma5121(W[40])+W[35]+sigma5120(W[27])+ W[26];
    W[43] = sigma5121(W[41])+W[36]+sigma5120(W[28])+ W[27];
    W[44] = sigma5121(W[42])+W[37]+sigma5120(W[29])+ W[28];
    W[45] = sigma5121(W[43])+W[38]+sigma5120(W[30])+ W[29];
    W[46] = sigma5121(W[44])+W[39]+sigma5120(W[31])+ W[30];
    W[47] = sigma5121(W[45])+W[40]+sigma5120(W[32])+ W[31];
    W[48] = sigma5121(W[46])+W[41]+sigma5120(W[33])+ W[32];
    W[49] = sigma5121(W[47])+W[42]+sigma5120(W[34])+ W[33];
    W[50] = sigma5121(W[48])+W[43]+sigma5120(W[35])+ W[34];
    W[51] = sigma5121(W[49])+W[44]+sigma5120(W[36])+ W[35];
    W[52] = sigma5121(W[50])+W[45]+sigma5120(W[37])+ W[36];
    W[53] = sigma5121(W[51])+W[46]+sigma5120(W[38])+ W[37];
    W[54] = sigma5121(W[52])+W[47]+sigma5120(W[39])+ W[38];
    W[55] = sigma5121(W[53])+W[48]+sigma5120(W[40])+ W[39];
    W[56] = sigma5121(W[54])+W[49]+sigma5120(W[41])+ W[40];
    W[57] = sigma5121(W[55])+W[50]+sigma5120(W[42])+ W[41];
    W[58] = sigma5121(W[56])+W[51]+sigma5120(W[43])+ W[42];
    W[59] = sigma5121(W[57])+W[52]+sigma5120(W[44])+ W[43];
    W[60] = sigma5121(W[58])+W[53]+sigma5120(W[45])+ W[44];
    W[61] = sigma5121(W[59])+W[54]+sigma5120(W[46])+ W[45];
    W[62] = sigma5121(W[60])+W[55]+sigma5120(W[47])+ W[46];
    W[63] = sigma5121(W[61])+W[56]+sigma5120(W[48])+ W[47];
    W[64] = sigma5121(W[62])+W[57]+sigma5120(W[49])+ W[48];
    W[65] = sigma5121(W[63])+W[58]+sigma5120(W[50])+ W[49];
    W[66] = sigma5121(W[64])+W[59]+sigma5120(W[51])+ W[50];
    W[67] = sigma5121(W[65])+W[60]+sigma5120(W[52])+ W[51];
    W[68] = sigma5121(W[66])+W[61]+sigma5120(W[53])+ W[52];
    W[69] = sigma5121(W[67])+W[62]+sigma5120(W[54])+ W[53];
    W[70] = sigma5121(W[68])+W[63]+sigma5120(W[55])+ W[54];
    W[71] = sigma5121(W[69])+W[64]+sigma5120(W[56])+ W[55];
    W[72] = sigma5121(W[70])+W[65]+sigma5120(W[57])+ W[56];
    W[73] = sigma5121(W[71])+W[66]+sigma5120(W[58])+ W[57];
    W[74] = sigma5121(W[72])+W[67]+sigma5120(W[59])+ W[58];
    W[75] = sigma5121(W[73])+W[68]+sigma5120(W[60])+ W[59];
    W[76] = sigma5121(W[74])+W[69]+sigma5120(W[61])+ W[60];
    W[77] = sigma5121(W[75])+W[70]+sigma5120(W[62])+ W[61];
    W[78] = sigma5121(W[76])+W[71]+sigma5120(W[63])+ W[62];
    W[79] = sigma5121(W[77])+W[72]+sigma5120(W[64])+ W[63];
  
  
  A = hash[0];
  B = hash[1];
  C = hash[2];
  D = hash[3];
  E = hash[4];
  F = hash[5];
  G = hash[6];
  H = hash[7];

  T1 = H + Sigma5121(E) + CH(E,F,G) + K[0] + W[0]; T2 = Sigma5120(A) + MAJ(A,B,C);
  X=D+T1; Y=T1+T2;
  T1 = G + Sigma5121(X) + CH(X,E,F) + K[1] + W[1]; T2 = Sigma5120(Y) + MAJ(Y,A,B);
  X1=C+T1; Y1= T1+T2;
  T1 = F + Sigma5121(X1) + CH(X1,X,E) + K[2] + W[2]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,A);
  X2= B+T1; Y2= T1+T2;  
  T1 = E + Sigma5121(X2) + CH(X2,X1,X) + K[3] + W[3]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=A + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[4] + W[4]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);
  X4= Y + T1; Y4=T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[5] + W[5]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);  
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[6] + W[6]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3);
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[7] + W[7]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[8] + W[8]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[9] + W[9]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[10] + W[10]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[11] + W[11]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3);  
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[12] + W[12]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[13] + W[13]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[14] + W[14]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);      
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[15] + W[15]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[16] + W[16]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3);  
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[17] + W[17]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[18] + W[18]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[19] + W[19]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);   
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[20] + W[20]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[21] + W[21]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3);
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[22] + W[22]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[23] + W[23]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[24] + W[24]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);      
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[25] + W[25]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[26] + W[26]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3); 
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[27] + W[27]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[28] + W[28]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[29] + W[29]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);      
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[30] + W[30]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[31] + W[31]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3);
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[32] + W[32]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[33] + W[33]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[34] + W[34]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);      
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[35] + W[35]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[36] + W[36]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3); 
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[37] + W[37]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[38] + W[38]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[39] + W[39]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);      
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[40] + W[40]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[41] + W[41]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3);
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[42] + W[42]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[43] + W[43]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[44] + W[44]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);      
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[45] + W[45]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[46] + W[46]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3);
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[47] + W[47]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[48] + W[48]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[49] + W[49]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);      
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[50] + W[50]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[51] + W[51]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3);
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[52] + W[52]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[53] + W[53]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[54] + W[54]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);      
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[55] + W[55]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[56] + W[56]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3);
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[57] + W[57]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[58] + W[58]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[59] + W[59]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);      
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[60] + W[60]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[61] + W[61]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3);
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[62] + W[62]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[63] + W[63]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[64] + W[64]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);      
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[65] + W[65]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[66] + W[66]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3);
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[67] + W[67]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[68] + W[68]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[69] + W[69]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);      
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[70] + W[70]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[71] + W[71]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3);
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[72] + W[72]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[73] + W[73]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[74] + W[74]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);      
  X4= Y + T1; Y4= T1 + T2;
  T1 = X1 + Sigma5121(X4) + CH(X4,X3,X2) + K[75] + W[75]; T2 = Sigma5120(Y4) + MAJ(Y4,Y3,Y2);
  X=Y1 + T1; Y=T1 + T2;
  T1 = X2 + Sigma5121(X) + CH(X,X4,X3) + K[76] + W[76]; T2 = Sigma5120(Y) + MAJ(Y,Y4,Y3);
  X1=Y2+T1; Y1= T1+T2;
  T1 = X3 + Sigma5121(X1) + CH(X1,X,X4) + K[77] + W[77]; T2 = Sigma5120(Y1) + MAJ(Y1,Y,Y4);
  X2=Y3 + T1; Y2=T1 + T2;
  T1 = X4 + Sigma5121(X2) + CH(X2,X1,X) + K[78] + W[78]; T2 = Sigma5120(Y2) + MAJ(Y2,Y1,Y);
  X3=Y4 + T1; Y3=T1 + T2;
  T1 = X + Sigma5121(X3) + CH(X3,X2,X1) + K[79] + W[79]; T2 = Sigma5120(Y3) + MAJ(Y3,Y2,Y1);
  X4= Y + T1; Y4= T1 + T2;   
 
  hash[0] +=Y4;
  hash[1] +=Y3;
  hash[2] +=Y2;
  hash[3] +=Y1;
  hash[4] +=X4;
  hash[5] +=X3;
  hash[6] +=X2;
  hash[7] +=X1;
  return;
}
