/*
  Test routine for Lesamnta-LW reference C99 implementation
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

#define _GNU_SOURCE

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lesamnta-LW.h"

#define NELMS(a) (sizeof(a)/sizeof(a[0]))


static void showUsage(const char *programName)
{
    fprintf(stderr, "%s [--help] [--testVector] file\n", programName);
}


static void showTestVector(void)
{
    /* Hash value */
    BitSequence hashval[LESAMNTALW_HASH_BITLENGTH / 8];

    /* Test vector 1
       Ref: IEICE Trans. vol.E95-A, no.1, 2012, p.97 */
    {
        BitSequence data[] = { 'a', 'b', 'c' };
        DataLength databitlen = NELMS(data) * 8;
        memset(hashval, 0x00, sizeof(hashval));
        Hash(LESAMNTALW_HASH_BITLENGTH, data, databitlen, hashval);
        printf("message: ");
        for (int i = 0; i < NELMS(data); ++i) {
            printf("%02x", data[i]);
        }
        printf("\n");
        printf("hashval: ");
        for (int i = 0; i < LESAMNTALW_HASH_BITLENGTH / 8; ++i) {
            printf("%02x", hashval[i]);
        }
        printf("\n");
        printf("Note: The hash value in the reference is incorrect.\n\n");
    }

    /* Test vector 2 */
    {
        BitSequence data[256/8] = { 0x00 };
        for (int i = 0; i < NELMS(data); ++i) {
            data[i] = (BitSequence)'L';
        }
        DataLength databitlen = NELMS(data) * 8;
        Hash(LESAMNTALW_HASH_BITLENGTH, data, databitlen, hashval);
        printf("message: ");
        for (int i = 0; i < NELMS(data); ++i) {
            printf("%02x", data[i]);
        }
        printf("\n");
        printf("hashval: ");
        for (int i = 0; i < LESAMNTALW_HASH_BITLENGTH / 8; ++i) {
            printf("%02x", hashval[i]);
        }
        printf("\n");
    }
}


int main(int argc, char *argv[])
{
    while (1) {
        static struct option long_options[] = {
            {"help", no_argument, NULL, 'h'},
            {"testVector", no_argument, NULL, 't'},
            {0, 0, 0, 0}
        };
        int c = getopt_long(argc, argv, "", long_options, NULL);
        if (c == -1) {
            break;
        } else if (c == 'h') {
            showUsage(argv[0]);
            exit(EXIT_SUCCESS);
        } else if (c == 't') {
            showTestVector();
            exit(EXIT_SUCCESS);
        } else {
            fprintf(stderr, "Not supported option: %x\n", c);
            exit(EXIT_FAILURE);
        }
    }

    /* A message is read from the file. */
    FILE *fp = fopen(argv[optind], "r");
    if (fp == NULL) {
        fprintf(stderr, "Not found: %s\n", argv[optind]);
        exit(EXIT_FAILURE);
    }
    BitSequence *data = malloc(BUFSIZ);
    if (data == NULL) {
        fprintf(stderr, "Not enough memory\n");
        exit(EXIT_FAILURE);
    }
    DataLength bytelen = 0;
    int c;
    while ((c = fgetc(fp)) != EOF) {
        data[bytelen] = (BitSequence)c;
        ++bytelen;
        if (bytelen % BUFSIZ == 0) {
            BitSequence *tmp = realloc(data, bytelen + BUFSIZ);
            if (tmp == NULL) {
                fprintf(stderr, "Not enough memory\n");
                exit(EXIT_FAILURE);
            } else {
                data = tmp;
            }
        }
    }
    DataLength databitlen = bytelen * 8;
    BitSequence hashval[LESAMNTALW_HASH_BITLENGTH / 8];
    Hash(LESAMNTALW_HASH_BITLENGTH, data, databitlen, hashval);
    printf("message: ");
    for (int i = 0; i < bytelen; ++i) {
            printf("%02x", data[i]);
    }
    printf("\n");
    printf("hashval: ");
    for (int i = 0; i < LESAMNTALW_HASH_BITLENGTH / 8; ++i) {
        printf("%02x", hashval[i]);
    }
    printf("\n");
    free(data);

    return 0;
}

/* end of file */
