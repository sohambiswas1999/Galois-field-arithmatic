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

uint64 poly[10];

uint64 hex2int(char hex)
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
char num1[64] = "7a23cf7fec37c07c5fb5c76dcea6fcab18639b651d836857a3b92f295ea5fc50";
char num2[64] = "4b72574b440c3242908bd43b110e0db65fa2267c10afd10b69a9e26555f9bd2c";

char a[64] = "84951adc7a73375eaeb99fc09c0633ed8a5f69bb13c8219057857504db29c1dd";
char b[64] = "e4ce92ff0fb08e9a0c9e33f369c5f73d9fb09ec7ef9b804a3d3c7435c3d418f9";

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
    poly[0] = h[31] | h[30] << 8 | h[29] << 16 | (h[28] & 0x1f) << 24;
    poly[1] = h[28] >> 5 | h[27] << 3 | h[26] << 11 | h[25] << 19 | (h[24] & 0x03) << 27;
    poly[2] = h[24] >> 2 | h[23] << 6 | h[22] << 14 | (h[21] & 0x7f) << 22;
    poly[3] = h[21] >> 7 | h[20] << 1 | h[19] << 9 | h[18] << 17 | (h[17] & 0x0f) << 25;
    poly[4] = h[17] >> 4 | h[16] << 4 | h[15] << 12 | h[14] << 20 | (h[13] & 0x01) << 28;
    poly[5] = h[13] >> 1 | h[12] << 7 | h[11] << 15 | (h[10] & 0x3f) << 23;
    poly[6] = h[10] >> 6 | h[9] << 2 | h[8] << 10 | h[7] << 18 | (h[6] & 0x07) << 26;
    poly[7] = h[6] >> 3 | h[5] << 5 | h[4] << 13 | h[3] << 21;
    poly[8] = h[2] | h[1] << 8 | h[0] << 16;
    poly[9] = 0;
}

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

void slice(uint64 *source, int start, int end)
{
    for (int i = start; i < end; i++)
    {
        printf("%llx\n", *(source + i));
    }
}

uint64_t *eightshiftofx(uint64 *poly)
{
    uint64 *p = (uint64 *)calloc(20, sizeof(uint64));
    p[0] = poly[8];
    p[1] = poly[9];
    p[2] = poly[10];
    p[3] = poly[11];
    p[4] = poly[12];
    p[5] = poly[13];
    p[6] = poly[14];
    p[7] = poly[15];
    p[8] = poly[16];
    p[9] = poly[17];

    return p;
}

uint64 *tenshift(uint64 *poly)
{
    uint64 *p = (uint64 *)calloc(10, sizeof(uint64));
    p[0] = poly[10];
    p[1] = poly[11];
    p[2] = poly[12];
    p[3] = poly[13];
    p[4] = poly[14];
    p[5] = poly[15];
    p[6] = poly[16];
    p[7] = poly[17];
    p[8] = poly[18];
    p[9] = poly[19];

    return p;
}

void HexToBin(char *hexdec)
{

    // Skips "0x" if present at beggining of Hex string
    size_t i = (hexdec[1] == 'x' || hexdec[1] == 'X') ? 2 : 0;

    while (hexdec[i])
    {

        switch (hexdec[i])
        {
        case '0':
            printf("0000");
            break;
        case '1':
            printf("0001");
            break;
        case '2':
            printf("0010");
            break;
        case '3':
            printf("0011");
            break;
        case '4':
            printf("0100");
            break;
        case '5':
            printf("0101");
            break;
        case '6':
            printf("0110");
            break;
        case '7':
            printf("0111");
            break;
        case '8':
            printf("1000");
            break;
        case '9':
            printf("1001");
            break;
        case 'A':
        case 'a':
            printf("1010");
            break;
        case 'B':
        case 'b':
            printf("1011");
            break;
        case 'C':
        case 'c':
            printf("1100");
            break;
        case 'D':
        case 'd':
            printf("1101");
            break;
        case 'E':
        case 'e':
            printf("1110");
            break;
        case 'F':
        case 'f':
            printf("1111");
            break;
        case '.':
            printf(".");
        default:
            printf("\nInvalid hexadecimal digit %c",
                   hexdec[i]);
        }
        i++;
    }
}

uint64 mult(uint64 *poly1, uint64 *poly2, uint64 *p)
{
    // uint64 p[20] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    // uint64 *p = (uint64 *)calloc(20, sizeof(uint64));
    uint64 carry = 0;
    for (int i = 0; i < 10; i++)
    {
        for (int j = 0; j < 10; j++)
        {
            // printf("multiplying: %llx,%llx\n", poly1[i], poly2[j]);
            p[i + j] = p[i + j] + (poly1[i] * poly2[j]);
            // printf("after mult:\n%llx\n", p[i + j]);
        }
    }

    for (int i = 0; i < 20; i++)
    {
        p[i] = p[i] + carry;
        // printf("after carry:\n%llx\n", p[i]);
        carry = p[i] >> 29;
        // printf("carry:\n%llx\n", carry);
        p[i] = p[i] & 0x1fffffff;
        //  printf("last 29 bits:\n%llx\n", p[i]);
    }
}

int geq(uint64 *poly1, uint64 *poly2)
{
    int flag = 1;
    for (int i = 9; i >= 0; i--)
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
    for (int i = 0; i < 10; i++)
    {
        p[i] = poly1[i] + (poly2[i] ^ 0x1fffffff) + carry;
        carry = p[i] >> 29;
        p[i] = p[i] & 0x1fffffff;
    }
}

void printarray(uint64 *poly)

{
    for (size_t i = 0; i < sizeof(poly); i++)
    {
        printf("%llx\n", poly[i]);
    }
}

void barret(uint64 *poly1, uint64 *r)
{ // initiate r with 0
    for (int i = 0; i < 10; i++)
    {
        r[i] = 0;
    }
    uint64 *X = (uint64 *)calloc(20, sizeof(uint64));
    for (int i = 0; i < 20; i++)
    {
        X[i] = poly1[i];
    }
    uint64 *Q = (uint64 *)calloc(10, sizeof(uint64));
    Q = eightshiftofx(X); // x/ theta^L-1
    // printf("Q:\n");
    // parse_to_hex(Q);

    uint64 Q2[20] = {0};

    uint64 T[10] = {0};
    parset(T, t);
    // parse_to_hex(T);

    uint64 P[10] = {0};
    parse(P, p);
    // parse_to_hex(P);

    mult(Q, T, Q2); // Q=QT
    // printf("QT:\n");
    // parse_to_hex(Q2);

    uint64 *te = tenshift(Q2);
    // printf("Q/theta^(L+1):");
    // parse_to_hex(te);

    uint64 Q3[20] = {0};
    mult(te, P, Q3); // Q/theta^L+1.p

    uint64 r1[10] = {0};

    // getting last 10 bit of QP i.e QP mod theta^L+1
    r1[0] = Q3[0];
    r1[1] = Q3[1];
    r1[2] = Q3[2];
    r1[3] = Q3[3];
    r1[4] = Q3[4];
    r1[5] = Q3[5];
    r1[6] = Q3[6];
    r1[7] = Q3[7];
    r1[8] = Q3[8];
    r1[9] = Q3[9];
    // printf("%llx\n", r1[9]);
    // printf("r1:\n");
    // parse_to_hex(r1);

    uint64 r3[10];
    // printf("X:\n");
    // parse_to_hex(X);

    sub(poly1, r1, r3);
    // printf("x-QP:");
    // parse_to_hex(r3);

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

void exprighttoleft(uint64 *poly1, uint64 *pow, uint64 *result)
{
    result[9] = 0;
    result[8] = 0;
    result[7] = 0;
    result[6] = 0;
    result[5] = 0;
    result[4] = 0;
    result[3] = 0;
    result[2] = 0;
    result[1] = 0;
    result[0] = 1;

    uint64 temp[20] = {0};
    for (int i = 0; i < 10; i++)
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
void main()
{
    uint64 poly1[10];
    uint64 poly2[10];

    uint16_t input4[32];
    uint16_t input5[32];

    chartoarray(num2, input4);
    chartoarray(num1, input5);

    parse(poly1, input4);
    parse(poly2, input5);

    printf("poly1\n");
    parse_to_hex(poly1);
    printf("poly2\n");
    parse_to_hex(poly2);

    uint64 poly3[10] = {0};

    /*mult(poly1, poly2, poly3);
     printf("result of mult\n");
     for (int i = 0; i < 20; i++)
     {
         printf("%llx\n", poly3[i]);
     }
     printf("input barret:\n");
     parse_to_hex(poly3);*/

    /*uint64 poly4[10] = {0};

    barret(poly3, poly4);

    for (int i = 0; i < 10; i++)
    {
        printf("%llx\n", poly4[i]);
    }

    parse_to_hex(poly4);*/

    exprighttoleft(poly1, poly2, poly3);
    printf("poly4\n");
    parse_to_hex(poly3);
}