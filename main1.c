#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef unsigned int uint32;
typedef char uint8;
typedef long long unsigned int uint64;

typedef struct
{
    uint64 x[10];
    uint64 y[10];
} point;

uint16_t input[32] = {0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x1b, 0x2b, 0x3b,
                      0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x1b, 0x2b, 0x3b,
                      0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x1b, 0x2b, 0x3b,
                      0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x1b, 0x2b, 0x3b};

uint16_t input1[32] = {0xf9, 0x2E, 0x40, 0xAD, 0x6F, 0x28, 0x1C, 0x8A,
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

static uint16_t pmin2[32] = {0xE9, 0x2E, 0x40, 0xAD, 0x6F, 0x28, 0x1C, 0x8A,
                             0x08, 0x2A, 0xFD, 0xC4, 0x9E, 0x13, 0x72, 0x65,
                             0x94, 0x55, 0xBE, 0xC8, 0xCE, 0xEA, 0x04, 0x3A,
                             0x61, 0x4C, 0x83, 0x5B, 0x7F, 0xE9, 0xEF, 0xF3};

uint64 poly[10];

char num1[64] = "7a23cf7fec37c07c5fb5c76dcea6fcab18639b651d836857a3b92f295ea5fc50";
char num2[64] = "4b72574b440c3242908bd43b110e0db65fa2267c10afd10b69a9e26555f9bd2c";

char a[64] = "84951adc7a73375eaeb99fc09c0633ed8a5f69bb13c8219057857504db29c1dd";
char b[64] = "e4ce92ff0fb08e9a0c9e33f369c5f73d9fb09ec7ef9b804a3d3c7435c3d418f9";

char genx[64] = "d824e020fda73095064e9e6506b30a8d9302d16916d35d4d2fe26dfca164bfd8";
char geny[64] = "816f2ccab116363a8e26640d716b6d7e2890b116cc81dcbd35f5a07753030233";

uint64
hex2int(char hex)
{

    if (hex >= '0' && hex <= '9')
        return hex - '0';
    else if (hex >= 'a' && hex <= 'f')
        return hex - 'a' + 10;
    else if (hex >= 'A' && hex <= 'F')
        return hex - 'A' + 10;
    perror("hex input not valid");
    exit(EXIT_FAILURE);
}

void chartoarray(char *num, uint16_t *array)
{
    for (int i = 0; i < 32; i++)
    {
        array[i] = 0;
    }
    for (int i = 0; i < 32; i++)
    {
        array[i] = hex2int(num[(2 * i) + 1]) + 16 * hex2int(num[(2 * i)]);
        // sprintf(array + i * 2)
    }
}

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
    temp[4] = bignum[1] >> 24 ^ bignum[0] << 5;
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
    int k, m;
    for (int i = 0; i < 10; i++)
    {
        for (int j = 0; j < 10; j++)
        {
            k = 9 - i;
            m = 9 - j;
            // printf("multiplying: %llx,%llx\n", poly1[i], poly2[j]);
            p[k + m + 1] = p[k + m + 1] + (poly1[k] * poly2[m]);
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

void add(uint64 *poly1, uint64 *poly2, uint64 *result)
{
    uint64 carry = 0;
    for (int i = 9; i >= 0; i--)
    {
        result[i] = poly1[i] + poly2[i] + carry;
        carry = result[i] >> 29;
        result[i] = result[i] & 0x1fffffff;
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
    // printf("T:\n");
    // parse_to_hex(T);

    uint64 P[10] = {0};
    parse(P, p);
    // printf("P:\n");
    // parse_to_hex(P);

    X = poly1 + 2;
    // printf("X:\n");
    // parse_to_hex(X);

    mult(poly1 + 2, T, Q2); // Q=XT
    // printf("QT:\n");
    // parse_to_hex(Q2);

    uint64 Q3[20] = {0};
    mult(Q2, P, Q3); // first 10 of XT i.e XT/theta^ * P

    uint64 *r2 = Q3 + 10;
    uint64 *r1 = poly1 + 10;

    // getting last 10 bit of QP i.e QP mod theta^L+1

    // printf("r1:\n");
    // parse_to_hex(r1);

    uint64 r3[10] = {0};
    // printf("X:\n");
    // parse_to_hex(X);

    sub(r1, r2, r3);
    // printf("x-QP:");
    // parse_to_hex(r3);

    for (int i = 0; i < 10; i++)
    {
        r[i] = r3[i];
    }

    if (geq(r3, P) == 1)
    {
        // printf("hi\n");
        sub(r3, P, r);
    }

    if (geq(r, P) == 1)
    {
        // printf("hi\n");
        sub(r, P, r3);
    }

    for (int i = 0; i < 10; i++)
    {
        r[i] = r3[i];
    }
}

void modadd(uint64 *poly1, uint64 *poly2, uint64 *result)
{
    uint64 prime[10] = {0};
    parse(prime, p);

    uint64 carry = 0;
    uint64 temp[10] = {0};
    for (int i = 9; i >= 0; i--)
    {
        temp[i] = poly1[i] + poly2[i] + carry;
        carry = temp[i] >> 29;
        temp[i] = temp[i] & 0x1fffffff;
    }

    if (geq(temp, prime) == 1)
    {
        sub(temp, prime, result);
    }
}

void modsub(uint64 *poly1, uint64 *poly2, uint64 *result)
{
    uint64 carry = 1;
    uint64 temp[10] = {0};
    uint64 prime[10] = {0};

    parse(prime, p);

    for (int i = 9; i >= 0; i--)
    {
        temp[i] = poly1[i] + (poly2[i] ^ 0x1fffffff) + carry;
        carry = temp[i] >> 29;
        temp[i] = temp[i] & 0x1fffffff;
    }

    if (geq(poly1, poly2) != 1)
    {
        add(temp, prime, result);
    }

    else
    {
        for (int i = 0; i < 10; i++)
        {
            result[i] = temp[i];
        }
    }
}

void exprighttoleft(uint64 *poly12, uint64 *pow1, uint64 *result)
{
    uint64 pow[10] = {0};
    uint64 poly1[10] = {0};

    for (int i = 0; i < 10; i++)
    {
        pow[i] = pow1[i];
        poly1[i] = poly12[i];
    }

    result[9] = 1;
    result[8] = 0;
    result[7] = 0;
    result[6] = 0;
    result[5] = 0;
    result[4] = 0;
    result[3] = 0;
    result[2] = 0;
    result[1] = 0;
    result[0] = 0;

    uint64 temp[20] = {0};
    for (int i = 9; i >= 0; i--)
    {
        for (int l = 0; l < 29; l++)
        {

            if (((pow[i] >> l) & 0x1) == 1)
            {
                for (int j = 0; j < 20; j++)
                    temp[j] = 0;

                mult(poly1, result, temp);
                barret(temp, result);
            }
            for (int j = 0; j < 20; j++)
                temp[j] = 0;

            mult(poly1, poly1, temp);
            barret(temp, poly1);
        }
    }
    printf("final result\n");
    parse_to_hex(result);
}

void explefttoright(uint64 *base, uint64 *pow, uint64 *result)
{
    uint64 temp[20] = {0};
    for (int i = 0; i < 10; i++)
    {
        for (int l = 28; l >= 0; l--)
        {
            int bit = (p[i] >> l) & 0x01;
            for (int j = 0; j < 20; j++)
                temp[j] = 0;

            mult(base, base, temp);
            barret(temp, result);

            if (bit == 1)
            {
                for (int j = 0; j < 20; j++)
                    temp[j] = 0;

                mult(base, result, temp);
                barret(temp, result);
            }
        }
    }
}

void modinv(uint64 *a, uint64 *result)
{
    uint64 psub2[10] = {0};

    parse(psub2, pmin2);

    printf("pmin2:\n");
    parse_to_hex(psub2);

    exprighttoleft(a, psub2, result);

    printf("result is\n");
    parse_to_hex(result);
}

uint64 modmult(uint64 *poly1, uint64 *poly2, uint64 *result)
{
    // uint64 p[20] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    // uint64 *p = (uint64 *)calloc(20, sizeof(uint64));
    uint64 carry = 0;
    uint64 p[20] = {0};
    int k, m;
    for (int i = 0; i < 10; i++)
    {
        for (int j = 0; j < 10; j++)
        {
            k = 9 - i;
            m = 9 - j;
            // printf("multiplying: %llx,%llx\n", poly1[i], poly2[j]);
            p[k + m + 1] = p[k + m + 1] + (poly1[k] * poly2[m]);
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

    barret(p, result);
}

void pointdoubling(point p1, point result)
{
    uint64 A[10] = {0};
    uint64 B[10] = {0};

    uint16_t inputa[32] = {0};
    uint16_t inputb[32] = {0};

    chartoarray(a, inputa);
    chartoarray(b, inputb);

    parse(A, inputa);
    parse(B, inputb);

    // computing X_2:
    uint64 tx1[10] = {0};
    uint64 tx2[10] = {0};
    uint64 ty1[10] = {0};
    uint64 ty2[10] = {0};
    uint64 t1[10] = {0};
    uint64 t2[10] = {0};
    uint64 t3[10] = {0};

    modmult(p1.x, p1.x, tx1); // tx1=x^2 mod p
    modadd(tx1, tx1, tx2);    // tx2=2.(x^2) mod p
    modadd(tx1, tx2, tx1);    // tx1=3.(x^2) mod p
    modadd(tx1, A, tx1);      // tx1=3.(x^2)+A mod p
    modadd(p1.y, p1.y, ty1);  // ty1=2y mod p
    modinv(ty1, ty2);         // ty2=1/(2y) mod p
    modmult(ty2, tx1, t1);    // t1=(3.(x^2)+A)/2y mod p
    modmult(t1, t1, t3);      // t3=((3.(x^2)+A)/2y)^2 mod p
    modadd(p1.x, p1.x, t2);   // t2=2x mod p
    modsub(t1, t2, result.x); // x_2=((3.(x^2)+A)/2y)^2 - 2x mod p

    // computing Y_2:

    // re-initialize the temp ver
    for (int i = 0; i < 10; i++)
    {
        tx1[i] = 0;
        tx2[i] = 0;
        ty1[i] = 0;
        ty2[i] = 0;
        t3[i] = 0;
        t2[i] = 0;
    }
    printf("p1.x:\n");
    parse_to_hex(p1.x);
    printf("result.x:\n");
    parse_to_hex(result.x);
    modsub(p1.x, result.x, tx1);

    printf("t1:\n");
    parse_to_hex(t1);
    printf("tx1:\n");
    parse_to_hex(tx1);
    modmult(t1, tx1, tx2);

    printf("tx2\n");
    parse_to_hex(tx2);
    printf("p1.y\n");
    parse_to_hex(p1.y);
    modsub(tx2, p1.y, t3);

    printf("outcome(x):");
    parse_to_hex(result.x);
    printf("outcome(y):");
    parse_to_hex(t3);
}

void main()
{
    point gen;
    point outcome = {{0}, {0}};

    uint16_t inputx[32];
    uint16_t inputy[32];

    chartoarray(genx, inputx);
    chartoarray(geny, inputy);

    parse(gen.x, inputx);
    parse(gen.y, inputy);

    printf("gen(x):\n");
    parse_to_hex(gen.x);
    printf("gen(y):\n");
    parse_to_hex(gen.y);

    /* uint16_t input4[32];
     uint16_t input5[32];

     chartoarray(num2, input4);
     chartoarray(num1, input5);

     uint64 poly1[10];
     uint64 poly2[10];

     parse(poly1, input4);
     parse(poly2, input5);

     printf("poly1\n");
     parse_to_hex(poly1);
     printf("poly2\n");
     parse_to_hex(poly2);

     uint64 poly3[10] = {0};
     uint64 poly4[10] = {0};
     uint64 poly5[10] = {0};*/
    // mult(poly1, poly2, poly3);
    //  printf("result of mult\n");
    /*for (int i = 19; i >= 0; i--)
    {
        printf("%llx\n", poly3[i]);
    }*/
    // printf("input barret:\n");
    // parse_to_hex(poly3 + 9);

    // uint64 outcome[10] = {0};

    // barret(poly3, outcome);

    /*for (int i = 0; i < 10; i++)
    {
        printf("%llx\n", poly4[i]);
    }*/

    // parse_to_hex(outcome);

    /* explefttoright(poly1, poly2, poly3);
     printf("poly3\n");
     parse_to_hex(poly3);

     exprighttoleft(poly1, poly2, poly4);
     printf("poly4\n");
     parse_to_hex(poly4);
     parse_to_hex(poly1);
     modinv(poly1, poly5);*/

    pointdoubling(gen, outcome);
}