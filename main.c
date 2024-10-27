#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef unsigned int uint32;
typedef char uint8;
typedef long long unsigned int uint64;

static uint16_t input[32] = {0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x1b, 0x2b, 0x3b,
                             0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x1b, 0x2b, 0x3b,
                             0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x1b, 0x2b, 0x3b,
                             0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x1b, 0x2b, 0x3b};

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

uint64 *mult(uint64 *poly1, uint64 *poly2, uint64 *p)
{
    // uint64 p[20] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    // uint64 *p = (uint64 *)calloc(20, sizeof(uint64));
    uint64 carry = 0;
    for (int i = 0; i < 10; i++)
    {
        for (int j = 0; j < 10; j++)
        {
            printf("multiplying: %llx,%llx\n", poly1[i], poly2[j]);
            p[i + j] = p[i + j] + (poly1[i] * poly2[j]);
            printf("after mult:\n%llx\n", p[i + j]);
        }
    }

    for (int i = 0; i < 20; i++)
    {
        p[i] = p[i] + carry;
        printf("after carry:\n%llx\n", p[i]);
        carry = p[i] >> 29;
        printf("carry:\n%llx\n", carry);
        p[i] = p[i] & 0x1fffffff;
        printf("last 29 bits:\n%llx\n", p[i]);
    }
}

int geq(uint64 *poly1, uint64 *poly2)
{
    int flag = 2;
    for (int i = 9; i >= 0; i--)
    {
        if (poly1[i] > poly2[i])
        {
            flag = 1;
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

void main()
{
    uint64 poly1[10];
    uint64 poly2[10];
    parse(poly1, input);
    parse(poly2, input);

    uint64 *poly3 = (uint64 *)calloc(20, sizeof(uint64));

    mult(poly1, poly2, poly3);
    for (int i = 0; i < 20; i++)
    {
        printf("%llx\n", poly3[i]);
    }
}