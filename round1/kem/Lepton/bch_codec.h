/* This file is based on the public domain implementation in
 * https://github.com/mborgerding/bch_codec
 * Ivan Djelic <ivan.djelic@parrot.com> and Mark Borgerding (mark@borgerding.net).
 * The program is modified to deal with bch codes with 5<=m<=9
 */
#ifndef _BCH_H
#define _BCH_H

#include <stdint.h>

/**
 * struct bch_control - BCH control structure
 * @m:          Galois field order
 * @n:          maximum codeword size in bits (= 2^m-1)
 * @t:          error correction capability in bits
 * @ecc_bits:   ecc exact size in bits, i.e. generator polynomial degree (<=m*t)
 * @ecc_bytes:  ecc max size (m*t bits) in bytes
 * @mod8_tab:   remainder generator polynomial lookup tables
 * @a_pow_tab:  Galois field GF(2^m) exponentiation lookup table
 * @a_log_tab:  Galois field GF(2^m) log lookup table
 * @xi_tab:     GF(2^m) base for solving degree 2 polynomial roots
 */
 
#define CACHE_SIZE 232 //> 2*(t+1)*sizeof(uint16_t)
 
 
struct bch_control {
	uint16_t    m;
	uint16_t    n;
	uint16_t    t;
	uint16_t    ecc_bits;
	uint16_t    ecc_bytes;

  uint8_t        mod8_tab[16384];
  uint16_t       xi_tab[9];
  uint16_t       a_log_tab[512];
  uint16_t       a_pow_tab[512];
};

void generate_BCH_paramaters(int m, int t, uint16_t prim_poly,char*filename);

void encode_bch(struct bch_control *bch, const uint8_t *data,
		uint16_t len, uint8_t *ecc);

int decode_bch(struct bch_control *bch, const uint8_t *data, uint16_t len,
	       const uint8_t *recv_ecc, uint16_t *errloc);

void correct_bch(uint8_t *data, uint16_t len, uint16_t *errloc, int nerr);


#endif /* _BCH_H */
