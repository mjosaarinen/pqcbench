/**
 *  random.h
 *  NTS-KEM
 *
 *  Parameter: NTS-KEM(13, 80)
 *  Platform: Intel 64-bit
 *
 *  This file is part of the optimized implemention of NTS-KEM
 *  submitted as part of NIST Post-Quantum Cryptography
 *  Standardization Process.
 **/

#ifndef __NTSKEM_RANDOM_H
#define __NTSKEM_RANDOM_H

#include <stdint.h>

/**
 *  Generate a random data of length `xlen` bytes
 *
 *  @note
 *  The output parameter `x` must not be NULL and
 *  it should have sufficient memory space allocated
 *
 *  @param[out] x    The output buffer holding the random data
 *  @param[in]  xlen The length of the random data
 *  @return an integer status value {@see nts_kem_errors.h}
 **/
int randombytes(unsigned char *x, unsigned long long xlen);

/**
 *  Instantiate the random number generator so that it
 *  produces a deterministic outputs
 *
 *  @note
 *  This method only has an effect for DRBG_AES random
 *  number generator
 *
 *  @param[in] entropy_input          The pointer to input entropy
 *                                    and it cannot be NULL
 *  @param[in] personalization_string The pointer to a buffer
 *                                    containing additional data.
 *                                    It can be NULL if no additional
 *                                    data is available
 *  @param[in] security_strength      The security strength in bits
 *                                    This parameter is redundant as the
 *                                    implementation assumes security
 *                                    strength of 256 bits
 **/
void randombytes_init(const unsigned char* entropy_input,
                      const unsigned char* personalization_string,
                      int security_strength);

/**
 *  Generate a 16-bit random number between 0 and `bound-1`
 *
 *  @param[in]  bound  The limit of the number to be generated
 *  @return a 16-bit random number
 **/
uint16_t random_uint16_bounded(uint16_t bound);

/**
 *  Return a uniform random bit
 *
 *  @return random bit 0 or 1
 **/
uint8_t randombit();

#endif /* __NTSKEM_RANDOM_H */
