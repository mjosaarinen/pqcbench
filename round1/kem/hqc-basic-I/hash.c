/**
 * \file utils.c
 * \brief Wrapper for OpenSSL SHA512
 */

#include "hash.h"

void sha512(unsigned char* output, unsigned char* input, uint64_t size) {
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, input, size);
    SHA512_Final(output, &sha512);
}
