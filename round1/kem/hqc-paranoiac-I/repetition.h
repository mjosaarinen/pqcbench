
/**
  * \file repetition.h
  * \brief Header file for repetition.c
  */

#ifndef REPETITION_H
#define REPETITION_H

#include <string.h>
#include "vector.h"

/**
 * \fn void repetition_code_encode(vector_u32* em, vector_u32* m)
 * \brief Encoding each bit in the message m using the repetition code
 *
 * For reasons of clarity and comprehensibility, we do the encoding by storing the encoded bits in a String (each bit in an unsigned char),
 * then we parse the obtained string to a vector using the function array_to_vector().
 *
 * \param[out] em a pointer to a vector that is the code word
 * \param[in] m a pointer to a vector that is the message
 */
void repetition_code_encode(vector_u32* em, vector_u32* m);

/**
 * \fn void array_to_vector(vector_u32* o, uint8_t* v)
 * \brief Parse an array to vector
 *
 * \param[out] o a pointer to a vector
 * \param[in] v a string 
 */
void array_to_vector(vector_u32* o, uint8_t* v);

/**
 * \fn void repetition_code_decode(vector_u32* m, vector_u32* em)
 * \brief Decoding the code words in the vector em to a message m using the repetition code
 *
 * We use a majority decoding. In fact we have that PARAM_N2 = 2 * PARAM_T + 1, thus,
 * if the Hamming weight of the vector is greater than PARAM_T, the code word is decoded
 * to 1 and 0 otherwise.
 *
 * The input to the decoding algorithm is supposed to be a vector of size UTILS_TENSOR_CODEWORD_ARRAY_SIZE (with PARAM_N1N2 bits). 
 * But in the function hqc_pke_decrypt(), the vector is of size UTILS_VECTOR_ARRAY_SIZE (with PARAM_N bits). Therefore
 * there are some extra-bits, we notice that we don't need to resize the input vector since the decoding 
 * algorithm will not be able to decode those extra bits. This is because that the dimension of the repetition code (PARAM_N2) is greater
 * than the number of the extra bits.
 *
 * \param[out] m a pointer to a vector that is the message
 * \param[in] em a pointer to a vector that is the code word
 */
void repetition_code_decode(vector_u32* m, vector_u32* em);

#endif