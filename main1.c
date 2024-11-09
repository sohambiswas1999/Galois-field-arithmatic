#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef unsigned int uint32;
typedef char uint8;
typedef long long unsigned int uint64;

uint16_t input[32] = {0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x1b, 0x2b, 0x3b,
                      0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x1b, 0x2b, 0x3b,
                      0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x1b, 0x2b, 0x3b,
                      0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x1b, 0x2b, 0x3b};
uint16_t input1[32] = {0xE9, 0x2E, 0x40, 0xAD, 0x6F, 0x28, 0x1C, 0x8A,
                       0x08, 0x2A, 0xFD, 0xC4, 0x9E, 0x13, 0x72, 0x65,
                       0x94, 0x55, 0xBE, 0xC8, 0xCE, 0xEA, 0x04, 0x3A,
                       0x61, 0x4C, 0x83, 0x5B, 0x7F, 0xE9, 0xEF, 0xF5};

static uint16_t t[34] = {0x46, 0x43, 0x5b, 0x5a, 0x40, 0xbb, 0xb8, 0xb9,
                         0x1a, 0x5a, 0xc8, 0x4a, 0x4a, 0x11, 0x80, 0x91,
                         0x5a, 0x5e, 0xea, 0xc0, 0x95, 0xbe, 0x5d, 0xc7,
                         0x5d, 0xda, 0xfa, 0x73, 0x02, 0x93, 0xae, 0x00, 0x01, 0x8};

static uint16_t p[32] = {0xE9, 0x2E, 0x40, 0xAD, 0x6F, 0x28, 0x1C, 0x8A,
                         0x08, 0x2A, 0xFD, 0xC4, 0x9E, 0x13, 0x72, 0x65,
                         0x94, 0x55, 0xBE, 0xC8, 0xCE, 0xEA, 0x04, 0x3A,
                         0x61, 0x4C, 0x83, 0x5B, 0x7F, 0xE9, 0xEF, 0xF5};

uint64 poly[10];

void parse(uint64 *poly, uint16_t *h)
{
    poly[9] = h[31] | h[30] << 8 | h[29] << 16 | (h[28] & 0x1f) << 24;
    poly[8] = h[28] >> 5 | h[27] << 3 | h[26] << 11 | h[25] << 19 | (h[24] & 0x03) << 27;
    poly[7] = h[24] >> 2 | h[23] << 6 | h[22] << 14 | (h[21] & 0x7f) << 22;
    poly[6] = h[21] >> 7 | h[20] << 1 | h[19] << 9 | h[18] << 17 | (h[17] & 0x0f) << 25;
    poly[5] = h[17] >> 4 | h[16] << 4 | h[15] << 12 | h[14] << 20 | (h[13] & 0x01) << 28;
    poly[4] = h[13] >> 1 | h[12] << 7 | h[11] << 15 | (h[10] & 0x3f) << 23;
    poly[3] = h[10] >> 6 | h[9] << 2 | h[8] << 10 | h[7] << 18 | (h[6] & 0x07) << 26;
    poly[2] = h[6] >> 3 | h[5] << 5 | h[4] << 13 | h[3] << 21;
    poly[1] = h[2] | h[1] << 8 | h[0] << 16;
    poly[0] = 0;
}

void parset(uint64 *poly, uint16_t *h)
{
    poly[9] = h[33] | h[32] << 4 | h[31] << 12 | h[30] << 20 | (h[29] & 0x01) << 28;
    poly[8] = h[27 + 2] >> 1 | h[26 + 2] << 7 | h[25 + 2] << 15 | (h[24 + 2] & 0x3f) << 23;
    poly[7] = h[24 + 2] >> 6 | h[23 + 2] << 2 | h[22 + 2] << 10 | h[21 + 2] << 18 | (h[22] & 0x07) << 26;
    poly[6] = h[20 + 2] >> 3 | h[19 + 2] << 5 | h[18 + 2] << 13 | h[17 + 2] << 21;
    poly[5] = h[16 + 2] | h[15 + 2] << 8 | h[14 + 2] << 16 | (h[13 + 2] & 0x1f) << 24;
    poly[4] = h[13 + 2] >> 5 | h[12 + 2] << 3 | h[11 + 2] << 11 | h[10 + 2] << 19 | (h[11] & 0x03) << 27;
    poly[3] = h[9 + 2] >> 2 | h[8 + 2] << 6 | h[7 + 2] << 14 | (h[6 + 2] & 0x7f) << 22;
    poly[2] = h[6 + 2] >> 7 | h[5 + 2] << 1 | h[4 + 2] << 9 | h[3 + 2] << 17 | (h[4] & 0x0f) << 25;
    poly[1] = h[2 + 2] >> 4 | h[1 + 2] << 4 | h[0 + 2] << 12 | h[1] << 20 | (h[0] & 0x01) << 28;
    poly[0] = h[0] >> 1;
}

void parse_to_hex(uint64 *bignum)
{
    uint64 temp[5] = {0};
    temp[5] = bignum[1] >> 24 ^ bignum[0] << 5;
    temp[3] = bignum[3] >> 18 ^ bignum[2] << 11 ^ bignum[1] << 40;
    temp[2] = bignum[5] >> 12 ^ bignum[4] << 17 ^ bignum[3] << 46;
    temp[1] = bignum[7] >> 6 ^ bignum[6] << 23 ^ bignum[5] << 52;
    temp[0] = bignum[9] ^ bignum[8] << 29 ^ bignum[7] << 58;
    for (int i = 0; i < 5; i++)
        printf("%llx\n", temp[i]);
}

uint64 mult(uint64 *poly1, uint64 *poly2, uint64 *p)
{
    // uint64 p[20] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    // uint64 *p = (uint64 *)calloc(20, sizeof(uint64));
    uint64 carry = 0;
    for (int i = 9; i >= 0; i--)
    {
        for (int j = 9; j >= 0; j--)
        {
            // printf("multiplying: %llx,%llx\n", poly1[i], poly2[j]);
            p[i + j] = p[i + j] + (poly1[i] * poly2[j]);
            // printf("after mult:\n%llx\n", p[i + j]);
        }
    }

    for (int i = 19; i >= 0; i--)
    {
        p[i] = p[i] + carry;
        // printf("after carry:\n%llx\n", p[i]);
        carry = p[i] >> 29;
        // printf("carry:\n%llx\n", carry);
        p[i] = p[i] & 0x1fffffff;
        // printf("last 29 bits:\n%llx\n", p[i]);
    }
}

int geq(uint64 *poly1, uint64 *poly2)
{
    int flag = 1;
    for (int i = 0; i < 10; i++)
    {
        if (poly1[i] > poly2[i])
        {

            break;
        }
        else if (poly1[i] < poly2[i])
        {
            flag = 0;
            break;
        }
    }
    return flag;
}

void sub(uint64 *poly1, uint64 *poly2, uint64 *p)
{
    uint64 carry = 1;
    for (int i = 9; i >= 0; i--)
    {
        p[i] = poly1[i] + (poly2[i] ^ 0x1fffffff) + carry;
        carry = p[i] >> 29;
        p[i] = p[i] & 0x1fffffff;
    }
}

void barret(uint64 *poly1, uint64 *r)
{ // initiate r with 0
    for (int i = 0; i < 10; i++)
    {
        r[i] = 0;
    }

    uint64 *X = (uint64 *)calloc(10, sizeof(uint64));

    uint64 Q2[20] = {0};

    uint64 T[10] = {0};
    parset(T, t);
    parse_to_hex(T);

    uint64 P[10] = {0};
    parse(P, p);
    parse_to_hex(P);

    X = poly1 + 8;
    printf("X:\n");
    parse_to_hex(X);

    mult(poly1, T, Q2); // Q=XT
    printf("QT:\n");
    parse_to_hex(Q2);

    uint64 Q3[20] = {0};
    mult(Q2, P, Q3); // first 10 of XT i.e XT/theta^ * P

    uint64 r1[10] = {0};

    // getting last 10 bit of QP i.e QP mod theta^L+1

    printf("%llx\n", r1[9]);
    printf("r1:\n");
    parse_to_hex(r1);

    uint64 r3[10];
    printf("X:\n");
    parse_to_hex(X);

    sub(poly1, r1, r3);
    printf("x-QP:");
    parse_to_hex(r3);

    if (geq(r3, P) == 1)
    {
        printf("hi\n");
        sub(r3, P, r);
    }

    if (geq(r, P) == 1)
    {
        printf("hi\n");
        sub(r, P, r3);
    }

    for (int i = 0; i < 10; i++)
    {
        r[i] = r3[i];
    }
}
void main()
{
    uint64 poly1[10];
    uint64 poly2[10];
    parse(poly1, input);
    parse(poly2, input);

    uint64 *poly3 = (uint64 *)calloc(20, sizeof(uint64));
    mult(poly1, poly2, poly3);
    printf("input barret:\n");
    parse_to_hex(poly3);

    uint64 poly4[10] = {0};

    barret(poly1, poly4);

    for (int i = 0; i < 10; i++)
    {
        printf("%llx\n", poly4[i]);
    }

    parse_to_hex(poly4);
}