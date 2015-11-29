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

#include <stdint.h>
#include <string.h>
#include "lesamnta-LW.h"

/* Lesamnta-LW parameters */
enum {
    /* Hash length */
    HashLengthInBit  = LESAMNTALW_HASH_BITLENGTH,
    HashLengthInByte = HashLengthInBit / 8,
    HashLengthInWord = HashLengthInBit / 32,
    /* Compression function */
    MessageBlockLengthInBit  = 128,
    MessageBlockLengthInByte = MessageBlockLengthInBit / 8,
    MessageBlockLengthInWord = MessageBlockLengthInBit / 32,
    /* Blockcipher part */
    NumberOfRounds = 64,
    KeyLengthInBit  = 128,
    KeyLengthInByte = KeyLengthInBit / 8,
    KeyLengthInWord = KeyLengthInBit / 32,
    BlockLengthInBit  = 256,
    BlockLengthInByte = BlockLengthInBit / 8,
    BlockLengthInWord = BlockLengthInBit / 32,
};

/* Initial values
   Ref: IEICE Trans. vol.E95-A, no.1, 2012, p.97 */
static const uint32_t initialValue[8] = {
    0x00000256U, 0x00000256U, 0x00000256U, 0x00000256U,
    0x00000256U, 0x00000256U, 0x00000256U, 0x00000256U,
};

/* AES-Encryption S-Box */
static const uint8_t sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* Round constants
   Ref: IEICE Trans. vol.E95-A, no.1, 2012, p.97 */
static const uint32_t C[64] = {
    0xa432337fU, 0x945e1f8fU, 0x92539a11U, 0x24b90062U,
    0x6971c64cU, 0xd6e3f449U, 0x2c2f0da9U, 0x33769295U,
    0xeb506df2U, 0x708cebfeU, 0xb83ab7bfU, 0x97df0f17U,
    0x9223b802U, 0x7fa29140U, 0x0ff45228U, 0x01fe8a45U,
    0xed016ee8U, 0x1da02dddU, 0xee8aba1bU, 0x46c4c223U,
    0x53cd0d24U, 0xd1b46d24U, 0xc1fb4124U, 0xc3f2a4a4U,
    0xc3b39814U, 0xc3bbbf82U, 0x759191b0U, 0x0eb23236U,
    0xb7fd6c86U, 0xa0d48750U, 0x141a90eaU, 0x6f65b45dU,
    0xe0d2092bU, 0x470fd445U, 0xe5df4528U, 0x1cbbe8a5U,
    0xeea9c2b4U, 0xc618f4d6U, 0xaee8345aU, 0x783be0cbU,
    0x5412e979U, 0x3c712e0fU, 0x87567c21U, 0x2619bca4U,
    0xdf0efb14U, 0xc02c13e2U, 0x75e3643cU, 0xd571a007U,
    0x9a766de0U, 0x134ecdbcU, 0xd9a41537U, 0x9becdb46U,
    0xa556b1a8U, 0x14aad635U, 0xefabe566U, 0xabde566cU,
    0xceb6064dU, 0xf4e87f69U, 0x286e7ccdU, 0xe8337039U,
    0x2bf51d27U, 0x85a6fa44U, 0xcb7913c8U, 0x196f2279U,
};


/* AES MixColumns and multiplications over GF(256) */
static uint8_t mul02(uint8_t v)
{
    uint16_t u = v << 1;
    if (u > 0xff) {
        u = u - 0x100;
        u = u ^ 0x1b;
    }
    return (uint8_t) u;
}

static uint8_t mul03(uint8_t v)
{
    return (uint8_t) (mul02(v) ^ v);
}

static uint8_t mul01(uint8_t v)
{
    return v;
}

static void MixColumns(uint8_t *s0, uint8_t *s1, uint8_t *s2, uint8_t *s3)
{
    uint8_t t0 = mul02(*s0) ^ mul03(*s1) ^ mul01(*s2) ^ mul01(*s3);
    uint8_t t1 = mul01(*s0) ^ mul02(*s1) ^ mul03(*s2) ^ mul01(*s3);
    uint8_t t2 = mul01(*s0) ^ mul01(*s1) ^ mul02(*s2) ^ mul03(*s3);
    uint8_t t3 = mul03(*s0) ^ mul01(*s1) ^ mul01(*s2) ^ mul02(*s3);
    *s0 = t0;
    *s1 = t1;
    *s2 = t2;
    *s3 = t3;
}

/* Function Q and packing/unpacking functions */
static uint32_t toUint32(uint8_t s0, uint8_t s1, uint8_t s2, uint8_t s3)
{
    return (((uint32_t) s0) << 24) |
        (((uint32_t) s1) << 16) | (((uint32_t) s2) << 8) | (((uint32_t) s3) << 0);
}

static void toUint8(uint8_t *s0, uint8_t *s1, uint8_t *s2, uint8_t *s3, uint32_t x)
{
    *s0 = (uint8_t) (x >> 24);
    *s1 = (uint8_t) (x >> 16);
    *s2 = (uint8_t) (x >>  8);
    *s3 = (uint8_t) (x >>  0);
}

static void functionQ(uint32_t *buf)
{
    uint8_t s0 = 0x00, s1 = 0x00, s2 = 0x00, s3 = 0x00;
    toUint8(&s0, &s1, &s2, &s3, *buf);
    s0 = sbox[s0];
    s1 = sbox[s1];
    s2 = sbox[s2];
    s3 = sbox[s3];
    MixColumns(&s0, &s1, &s2, &s3);
    *buf = toUint32(s0, s1, s2, s3);
}

/* Function R */
static void functionR(uint32_t *buf)
{
    uint8_t s[8] = { 0x00 };
    toUint8(s + 0, s + 1, s + 2, s + 3, buf[0]);
    toUint8(s + 4, s + 5, s + 6, s + 7, buf[1]);
    buf[0] = toUint32(s[4], s[5], s[2], s[3]);
    buf[1] = toUint32(s[0], s[1], s[6], s[7]);
}

/* Function G */
static void functionG(uint32_t *output, uint32_t key, const uint32_t *input)
{
    uint32_t buf[2] = { 0x00 };
    memcpy(buf, input, sizeof(buf));
    buf[0] ^= key;
    functionQ(buf + 0);
    functionQ(buf + 1);
    functionR(buf);
    memcpy(output, buf, sizeof(buf));
}

/* Key schedule */
static void keySchedule(uint32_t *roundKey, const uint32_t *key)
{
    uint32_t k[KeyLengthInWord] = { 0x00 };
    memcpy(k, key, sizeof(k));

    for (int round = 0; round < NumberOfRounds; ++round) {
        roundKey[round] = k[0];
        uint32_t buf = C[round] ^ k[2];
        functionQ(&buf);
        buf ^= k[3];

        k[3] = k[2];
        k[2] = k[1];
        k[1] = k[0];
        k[0] = buf;
    }
}

/* Message mixing function */
static void messageMixing(uint32_t *block, const uint32_t *roundKey)
{
    for (int round = 0; round < NumberOfRounds; ++round) {
        uint32_t buf[2] = { 0x00 };
        functionG(buf, roundKey[round], block + 4);
        buf[0] ^= block[6];
        buf[1] ^= block[7];

        block[7] = block[5];
        block[6] = block[4];
        block[5] = block[3];
        block[4] = block[2];
        block[3] = block[1];
        block[2] = block[0];
        block[1] = buf[1];
        block[0] = buf[0];
    }
}

/* Blockcipher encryption used in Lesamnta-LW */
static void blockCipher(uint32_t *ciphertext, const uint32_t *key, const uint32_t *plaintext)
{
    uint32_t roundKey[NumberOfRounds] = { 0x00 };
    keySchedule(roundKey, key);
    uint32_t block[BlockLengthInWord] = { 0x00 };
    memcpy(block, plaintext, sizeof(block));
    messageMixing(block, roundKey);
    memcpy(ciphertext, block, sizeof(block));
}


/* ***************************************************************** */
/* SHA-3 API: Internal state */
typedef struct {
    int hashbitlen;
	uint32_t messageLength[2];
	uint32_t remainingLength;
	uint32_t message[MessageBlockLengthInWord];
	uint32_t hash[HashLengthInWord];
} hashState;

/*
  SHA-3 API: Init() initializes a hashState with the intended hash
  length of this particular instantiation.  Additionally, any data
  independent setup is performed.

  Parameters:
  - state: a structure that holds the hashState information
  - hashbitlen: an integer value that indicates the length of the hash
  output in bits.
  Returns:
  - Success value.
*/
static HashReturn Init(hashState *state, int hashbitlen)
{
    /* The hash length is 256. */
    if (hashbitlen != HashLengthInBit) {
        return BAD_HASHBITLEN;
    } else {
        state->hashbitlen = hashbitlen;
    }
    /* messageLength[0] is the most significant word. */
    state->messageLength[0] = 0;
    state->messageLength[1] = 0;
    state->remainingLength = 0;
    memset(state->message, 0x00, MessageBlockLengthInByte);
    memcpy(state->hash, initialValue, HashLengthInByte);

    return SUCCESS;
}

static void setMessage(uint32_t *message, const BitSequence *data)
{
    memset(message, 0x00, MessageBlockLengthInByte);
    for (int i = 0; i < MessageBlockLengthInByte; ++i) {
        message[i / 4] |= ((uint32_t) data[i]) << (24 - 8 * (i % 4));
    }
}

static void setRemainingMessage(uint32_t *message, uint32_t remainingLength, const BitSequence *data)
{
    memset(message, 0x00, MessageBlockLengthInByte);
    int last = remainingLength / 8 + (remainingLength % 8 == 0 ? -1 : 0);
    for (int i = 0; i <= last; ++i) {
        message[i / 4] |= ((uint32_t) data[i]) << (24 - 8 * (i % 4));
    }
}

/* Compression function */
static void compressionFunction(uint32_t *hash, const uint32_t *message)
{
    uint32_t key[KeyLengthInWord] = { 0x00 };
    uint32_t plaintext[BlockLengthInWord] = { 0x00 };
    memcpy(key, hash, sizeof(key));
    memcpy(plaintext, message, sizeof(plaintext) / 2);
    memcpy(plaintext + 4, hash + 4, sizeof(plaintext) / 2);
    uint32_t ciphertext[BlockLengthInWord] = { 0x00 };
    blockCipher(ciphertext, key, plaintext);
    memcpy(hash, ciphertext, sizeof(ciphertext));
}

/*
  SHA-3 API: Update() processes data using the compression function.
  Whatever integral amount of data the Update() routine can process
  through the compression function is handled. Any remaining data must
  be stored for future processing.

  Parameters:
  - state: a structure that holds the hashState information
  - data: the input data to be hashed
  - databitlen: the length, in bits, of the input data to be hashed
  Returns:
  - Success value.
*/
static HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen)
{
    /* messageLength[0] is the most significant word． */
    state->messageLength[0] = (uint32_t)(databitlen >> 32);
    state->messageLength[1] = (uint32_t)databitlen;

    /* Apply the compression function. */
    while (databitlen >= MessageBlockLengthInBit) {
        setMessage(state->message, data);
        compressionFunction(state->hash, state->message);
        data += MessageBlockLengthInByte;
        databitlen -= MessageBlockLengthInBit;
    }

    state->remainingLength = databitlen;
    memset(state->message, 0x00, MessageBlockLengthInByte);
    if (state->remainingLength != 0) {
        setRemainingMessage(state->message, state->remainingLength, data);
    }

    return SUCCESS;
}

/* Padding function */
static void paddingMessage(uint32_t *message, uint32_t remainingLength)
{
    int last = remainingLength / 32;
    message[last] |= 0x00000001U << (31 - (remainingLength % 32));
}

static void toBitSequence256(BitSequence *hashval, const uint32_t *hash)
{
    for (int i = 0; i < HashLengthInByte; i += 4) {
        hashval[i + 0] = (BitSequence) (hash[i / 4] >> 24);
        hashval[i + 1] = (BitSequence) (hash[i / 4] >> 16);
        hashval[i + 2] = (BitSequence) (hash[i / 4] >> 8);
        hashval[i + 3] = (BitSequence) (hash[i / 4] >> 0);
    }
}

/*
  SHA-3 API: Final() processes any remaining partial block of the
  input data and performs any output filtering that may be needed to
  produce the final hash value.  This function is called with pointers
  to the appropriate hashState structure and the storage for the final
  hash value to be returned (hashval). It performs any post processing
  that is necessary, including the handling of any partial blocks, and
  places the final hash value in hashval. Lastly, an appropriate
  status value is returned.

  Parameters:
  - state: a structure that holds the hashState information
  - hashval: the storage for the final (output) hash value to be returned
  Returns:
  - Success value.
*/
static HashReturn Final(hashState *state, BitSequence *hashval)
{
    /* Is the message length a multiple of the block length? */
    if (state->remainingLength == 0) {
        state->message[0] = 0x80000000U;
    } else {
        paddingMessage(state->message, state->remainingLength);
        compressionFunction(state->hash, state->message);
        state->message[0] = 0x00000000U;
    }
    state->message[1] = 0x00000000U;
    state->message[2] = state->messageLength[0];
    state->message[3] = state->messageLength[1];

    /* Last compression function */
    compressionFunction(state->hash, state->message);
    state->remainingLength = 0;
    memset(state->message, 0x00, sizeof(state->message));

    toBitSequence256(hashval, state->hash);

    return SUCCESS;
}

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
                DataLength databitlen, BitSequence *hashval)
{
    hashState state;
    HashReturn ret = Init(&state, hashbitlen);
    if (ret != SUCCESS) {
        return ret;
    }
    ret = Update(&state, data, databitlen);
    if (ret != SUCCESS) {
        return ret;
    }
    ret = Final(&state, hashval);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

/* end of file */
