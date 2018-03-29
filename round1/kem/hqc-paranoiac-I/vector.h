
/**
  * \file vector.h
  * \brief Header file for vector.c
  */

#ifndef VECTOR_H
#define VECTOR_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> 
#include <string.h>

#include "parameters.h"
#include "hash.h"
#include "rng.h"

/**
 * \struct vector_u32
 * \brief a structure of a vector 
 *
 * This structure allows to storage vectors in two different forms. 
 * The first one is a storage by coordinate. In this form we 
 * consider that the vector can be stored as an array of binary bits. 
 * The coordinates of the vector are stored in an uint32_t array,
 * where each element in the array stores 32 coordinates of the vector.
 * The second one is 
 * a storage by position. Since we deal with vector with a small Hamming
 * weight, we can represent those vectors using their support, i.e the
 * set of indices of the nonzero coordinates. In this case, each element
 * of the array of this structure contains an element of the support 
 * of the vector stored as a uint32_t element. For example, the vector
 * 1000100100 is stored as [0, 4, 7]).   
 *
 * The structure contains an array that can store either the coordinates or the 
 * support of a vector. The variable dim indicates the size of the array. The 
 * flag (by_position_flag) is set to 1 when the vector is stored by position and 0
 * when it's stored by coordinate.
 */
typedef struct vector_u32 {
	uint32_t 	dim;  /*!< The size of the array*/   
  uint32_t* value; /*!< An array of uint32_t that is the coordinates or the positions of a vector*/
  int8_t by_position_flag; /*!< A flag that indicates the storage format of the element of a vector (storage by coordinate or by position).
    This value is set to -1 by default, to 0 if the vector is stored by coordinate and to 1 when the vector is stored by position */                            
} vector_u32;

/**
 * \fn vector_u32* vector_u32_init(const uint32_t dim)
 * \brief Initializes the structure vector_u32
 *
 * This function is used to initialize vectors by allocating the necessary
 * memory for a vector that can be stored by coordinate or by position.
 * When it's used for vector stored by coordinate, the input parameter 
 * is the size of a uint32_t array that can store by coordinate a vector of a given dimension. For instance, 
 * suppose that the dimension of the vector is equal to <b>PARAM_N</b>. To store this vector, 
 * we need a uint32_t array of size <b>UTILS_VECTOR_ARRAY_SIZE</b>, where:
 * <CENTER> <b>UTILS_VECTOR_ARRAY_SIZE</b> = <b>(PARAM_N / 32) + 1)</b></CENTER>When
 * it's used for vector stored by position, the input parameter is the Hamming weight of the vector.
 * 
 *
 * \param[in] dim a uint32_t that is the size of a uint32_t array that can store a vector by coordinate or the Hamming weight of a vector.
 * \return a pointer to a vector
 */
vector_u32* vector_u32_init(const uint32_t dim);

/**
 * \fn void vector_u32_clear(vector_u32* v)
 * \brief Free the allocated memory for a the structure vector_u32
 *
 * \param[in] v a pointer to a vector_u32
 */
void vector_u32_clear(vector_u32* v);

/**
 * \fn int vector_u32_compare(vector_u32* v1, vector_u32* v2)
 * \brief Compares two vectors
 *
 * \param[in] v1 a pointer to a vector_u32
 * \param[in] v2 a pointer to a vector_u32
 * \return 1 if the input vectors are equals and 0 otherwise
 */
int vector_u32_compare(vector_u32* v1, vector_u32* v2);

/**
 * \fn void vector_u32_add(vector_u32* o, vector_u32* v1, vector_u32* v2)
 * \brief Adds two vectors
 *
 * This function adds two vectors the addition is done modulo 2.
 * The input vectors must be one of the following cases:
 *  - both vectors are stored by coordinate
 *  - a vector stored by position and the other one stored by coordinate (the order of input vectors doesn't matter)
 *
 * The output vector, in all cases, is stored by coordinate.
 *
 * \param[out] o a pointer to the resulting vector
 * \param[in] v1 a pointer to the first vector 
 * \param[in] v2 a pointer to the second vector
 */
void vector_u32_add(vector_u32* o, vector_u32* v1, vector_u32* v2);

/**
 * \fn void vector_u32_add_by_coordinate(vector_u32* o, vector_u32* v1, vector_u32* v2)
 * \brief Adds two vectors stored by coordinate
 *
 * \param[out] o a pointer to the resulting vector
 * \param[in] v1 a pointer to the first vector 
 * \param[in] v2 a pointer to the second vector
 */
void vector_u32_add_by_coordinate(vector_u32* o, vector_u32* v1, vector_u32* v2);

/**
 * \fn void vector_u32_add_by_position_and_coordinate(vector_u32* o, vector_u32* v1, vector_u32* v2)
 * \brief Adds two vectors stored in different forms
 *
 * This function adds two vectors: one stored by position and the 
 * the other one stored by coordinate. The vector <b>v1</b> must be stored by position and
 * the vector <b>v2</b> must be stored by coordinate.
 *
 * \param[out] o a pointer to the resulting vector
 * \param[in] v1 a pointer to the first vector 
 * \param[in] v2 a pointer to the second vector
 */
void vector_u32_add_by_position_and_coordinate(vector_u32* o, vector_u32* v1, vector_u32* v2);

/**
 * \fn void vector_u32_mul(vector_u32* o, vector_u32* v1, vector_u32* v2)
 * \brief Multiplies two vectors stored in different forms
 *
 * This function multiplies two vectors: one stored by position and the 
 * the other one stored by coordinate. The vector <b>v1</b> must be stored by position and
 * the vector <b>v2</b> must be stored by coordinate.
 * For more details on this algorithm see the document <a href="../doc_mul.pdf" target="_blank"><b>multiplication algorithm</b></a>.
 *
 * \param[out] o a pointer to a vector stored by coordinate that is the result of the multiplication 
 * \param[in] v1 a pointer to a vector  
 * \param[in] v2 a pointer to a vector 
 */
void vector_u32_mul(vector_u32* o, vector_u32* v1, vector_u32* v2);

/**
 * \fn int vector_u32_mul_precompute_rows(uint32_t* o, const uint32_t* v)
 * \brief A subroutine used in the function vector_u32_mul().
 *
 * For more details on this algorithm see the document <a href="../doc_mul.pdf" target="_blank"><b>multiplication algorithm</b></a>.
 *
 * \param[out] o a pointer to an array
 * \param[in] v a pointer to an array
 * \return 0 if precomputation is successful, -1 otherwise
 */
int vector_u32_mul_precompute_rows(uint32_t* o, const uint32_t* v);

/**
 * \fn void vector_u32_extend(vector_u32* o, vector_u32* v)
 * \brief Put a vector in a bigger vector
 *
 * \param[out] o a pointer to a vector
 * \param[in] v a pointer to a vector
 */
void vector_u32_extend(vector_u32* o, vector_u32* v); 

/**
 * \fn void vector_u32_fixed_weight(vector_u32* v, const uint16_t weight, AES_XOF_struct* ctx)
 * \brief Generates a vector of a given Hamming weight
 *
 * This function generates uniformly at random a binary vector of a Hamming weight equal to the parameter <b>weight</b>. The vector 
 * is stored by position. 
 * To generate the vector we have to sample uniformly at random values in the interval [0, PARAM_N -1]. Suppose the PARAM_N is equal to \f$ 70853 \f$, to select a position \f$ r\f$ the function works as follow:
 *  1. It makes a call to the seedexpander function to obtain a random number \f$ x\f$ in \f$ [0, 2^{24}[ \f$.
 *  2. Let \f$ t = \lfloor {2^{24} \over 70853} \rfloor \times  70853\f$
 *  3. If \f$ x \geq t\f$, go to 1
 *  4. It return \f$ r = x \mod 70853\f$ 
 *
 * The parameter \f$ t \f$ is precomputed and it's denoted by UTILS_REJECTION_THRESHOLD (see the file parameters.h).
 *
 * \param[in] v a pointer to a vector
 * \param[in] weight an integer that is the Hamming weight
 * \param[in] ctx a pointer to the context of the seed expander
 */
void vector_u32_fixed_weight(vector_u32* v, const uint16_t weight, AES_XOF_struct* ctx);

/**
 * \fn void vector_u32_set_random(vector_u32* v, AES_XOF_struct* ctx)
 * \brief Generates a random vector of dimension <b>PARAM_N</b>
 *
 * This function generates a random binary vector of dimension <b>PARAM_N</b> stored by coordinate. First, it generates a random 
 * array of bytes using the seedexpander function. Then, since <b>PARAM_N</b> is not a multiple of 32, 
 * we set to zero the extra bits in the last element of <b>v->value</b>. We achieve this, by using a recomputed mask <b>UTILS_MASK</b> (see the parameters.h).
 *
 * \param[in] v a pointer to a vector 
 * \param[in] ctx a pointer to the context of the seed expander
 */
void vector_u32_set_random(vector_u32* v, AES_XOF_struct* ctx);

/**
 * \fn void vector_u32_set_random_from_randombytes(vector_u32* v)
 * \brief Generates a random vector
 *
 * This function generates a random binary vector stored by coordinate. It uses the the randombytes function.
 *
 * \param[in] v a pointer to a vector 
 */
void vector_u32_set_random_from_randombytes(vector_u32* v);

/**
 * \fn void vector_u32_print(vector_u32* v, int param)
 * \brief Prints a vector
 *
 * Depending on the storage type (positions or coordinates) of the vector and its size, it prints its content in form of hexadecimals or positions. 
 *
 * \param[in] v a pointer to a vector 
 * \param[in] param an integer that is the dimension of the vector 
 */
void vector_u32_print(vector_u32* v, int param);

/**
 * \fn void print_bytes(uint32_t value, int size)
 * \brief Prints a given number of bytes stored in an integer
 *
 * \param[in] value a pointer to an integer
 * \param[in] size an integer that is number of bytes to be displayed
 */
void print_bytes(uint32_t value, int size);
#endif