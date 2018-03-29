/**
 *  main.c
 *  NTS-KEM
 *
 *  Parameter: NTS-KEM(13, 80)
 *  Platform: Intel 64-bit
 *
 *  This file is part of the optimized implemention of NTS-KEM
 *  submitted as part of NIST Post-Quantum Cryptography
 *  Standardization Process.
 **/

#include <stdio.h>
#include <stdint.h>
#include "random.h"
#include "ntskem_test.h"

static const unsigned char entropy_input[48] = {
    0x2d, 0x4c, 0x9f, 0x46, 0xb9, 0x81, 0xc6, 0xa0,
    0xb2, 0xb5, 0xd8, 0xc6, 0x93, 0x91, 0xe5, 0x69,
    0xff, 0x13, 0x85, 0x14, 0x37, 0xeb, 0xc0, 0xfc,
    0x00, 0xd6, 0x16, 0x34, 0x02, 0x52, 0xfe, 0xd5,
    0x8e, 0x39, 0xb2, 0x27, 0x12, 0x92, 0x0e, 0xfd,
    0xda, 0xe0, 0x2c, 0x6f, 0xdc, 0xa5, 0x97, 0x8c
};
static const char* nonce = "0bf814b411f65ec4866be1abb59d3c32a57b9037e01f429c";
                            
int main(int argc, char *argv[])
{
    int status;
    
    randombytes_init(entropy_input, (const unsigned char *)nonce, 256);
    status = testkem_nts(500);
    printf("NTS-KEM(%d, %d) test: %s\n", NTSKEM_M, NTSKEM_T, status ? "PASS" : "FAIL");

    return 0;
}
