#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef unsigned int uint32;
typedef char uint8;
typedef long long unsigned int uint64;

static uint16_t t[34] = {0x46, 0x43, 0x5b, 0x5a, 0x40, 0xbb, 0xb8, 0xb9,
                         0x1a, 0x5a, 0xc8, 0x4a, 0x4a, 0x11, 0x80, 0x91,
                         0x5a, 0x5e, 0xea, 0xc0, 0x95, 0xbe, 0x5d, 0xc7,
                         0x5d, 0xda, 0xfa, 0x73, 0x02, 0x93, 0xae, 0x00, 0x01, 0x8};

void parset(uint64 *poly, uint16_t *h)
{
    poly[0] = h[33] | h[32] << 4 | h[31] << 12 | h[30] << 20 | (h[29] & 0x01) << 28;
    poly[1] = h[27 + 2] >> 1 | h[26 + 2] << 7 | h[25 + 2] << 15 | (h[24 + 2] & 0x3f) << 23;
    poly[2] = h[24 + 2] >> 6 | h[23 + 2] << 2 | h[22 + 2] << 10 | h[21 + 2] << 18 | (h[22] & 0x07) << 26;
    poly[3] = h[20 + 2] >> 3 | h[19 + 2] << 5 | h[18 + 2] << 13 | h[17 + 2] << 21;
    poly[4] = h[16 + 2] | h[15 + 2] << 8 | h[14 + 2] << 16 | (h[13 + 2] & 0x1f) << 24;
    poly[5] = h[13 + 2] >> 5 | h[12 + 2] << 3 | h[11 + 2] << 11 | h[10 + 2] << 19 | (h[11] & 0x03) << 27;
    poly[6] = h[9 + 2] >> 2 | h[8 + 2] << 6 | h[7 + 2] << 14 | (h[6 + 2] & 0x7f) << 22;
    poly[7] = h[6 + 2] >> 7 | h[5 + 2] << 1 | h[4 + 2] << 9 | h[3 + 2] << 17 | (h[4] & 0x0f) << 25;
    poly[8] = h[2 + 2] >> 4 | h[1 + 2] << 4 | h[0 + 2] << 12 | h[1] << 20 | (h[0] & 0x01) << 28;
    poly[9] = h[0] >> 1;
}

void parse_to_hex(uint64 *bignum)
{
    uint64 temp[5] = {0};
    temp[4] = bignum[8] >> 24 ^ bignum[9] << 5;
    temp[3] = bignum[6] >> 18 ^ bignum[7] << 11 ^ bignum[8] << 40;
    temp[2] = bignum[4] >> 12 ^ bignum[5] << 17 ^ bignum[6] << 46;
    temp[1] = bignum[2] >> 6 ^ bignum[3] << 23 ^ bignum[4] << 52;
    temp[0] = bignum[0] ^ bignum[1] << 29 ^ bignum[2] << 58;
    for (int i = 0; i < 5; i++)
        printf("%llx\n", temp[i]);
}

void printarray(uint64 *poly)

{
    printf("%d\n", sizeof(poly));
    for (int i = 0; i < sizeof(poly); i++)
    {
        printf("%llx\n", poly[i]);
    }
}

int main()
{
    uint64 poly[10];
    parset(poly, t);
    for (int i = 0; i < 10; i++)
    {
        printf("%llx\n", poly[i]);
    }

    parse_to_hex(poly);
}