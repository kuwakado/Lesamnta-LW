/*
  Lesamnta-LW reference C99 implementation

  The code is based on reference [1].  APIs are the same as those of
  the SHA-3 competition.

  Reference
  [1] S. Hirose, K. Ideguchi, H. Kuwakado, T. Owada, B. Preneel, and H. Yoshida,
      "An AES based 256-bit hash function for lightweight applications: Lesamnta-LW,"
      IEICE TRANSACTIONS on Fundamentals of Electronics, Communications and Computer Sciences,
      Vol.E95-A, No.1, pp.89-99, 2012/01/01.

  Note: Lesamnta is a registered trademark of Hitachi, Ltd. in Japan.


  Released under the MIT license
  Copyright (C) 2015 Hidenori Kuwakado

  Permission is hereby granted, free of charge, to any person
  obtaining a copy of this software and associated documentation files
  (the "Software"), to deal in the Software without restriction,
  including without limitation the rights to use, copy, modify, merge,
  publish, distribute, sublicense, and/or sell copies of the Software,
  and to permit persons to whom the Software is furnished to do so,
  subject to the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

#ifndef ___LESAMNTALW_H
#define ___LESAMNTALW_H

/* The Lesamnta-LW hash length is 256 only. */
#define LESAMNTALW_HASH_BITLENGTH 256

/* The type of the input data */
typedef unsigned char BitSequence;

/* The data length type */
typedef uint64_t DataLength;

/* The success code values */
typedef enum {
/* Successfully computed the hash value */
	SUCCESS = 0,
/* Failed to compute the hash value */
	FAIL = 1,
/* Unsupported hash bit length */
	BAD_HASHBITLEN = 2,
} HashReturn;

/*
  SHA-3 API: Hash() provides a method to perform all-at-once
  processing of the input data and returns the resulting hash
  value. The Hash() function is called with a pointer to the data to
  be processed, the length of the data to be processed (databitlen), a
  pointer to the storage for the resulting hash value (hashval), and a
  length of the desired hash value (hashbitlen). This function
  utilizes the previous three function calls, namely Init(), Update(),
  and Final().

  Parameters:
  - hashbitlen: the length in bits of the desired hash value
  - data: the input data to be hashed
  - databitlen: the length, in bits, of the data to be hashed
  - hashval: the resulting hash value of the provided data
  Returns:
  - Success value.
*/
HashReturn Hash(int hashbitlen, const BitSequence *data,
                DataLength databitlen, BitSequence *hashval);


#endif  /* ___LESAMNTALW_H */

/* end of file */
