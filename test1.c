#include <stdio.h>
#include <stdlib.h>

typedef long long unsigned int u64;
typedef unsigned int u32;
typedef unsigned char u8;

u64 m[10] = {0};
u64 mu[10] = {0};
u64 g[10] = {0};

static char t[] = "46435b5a40bbb8b91a5ac84a4a1180915a5eeac095be5dc75ddafa730293ae00018";

// Function to convert a hexadecimal string to an array of u32
u64 hextoint(char hex)
{
    if (hex >= '0' && hex <= '9')
    {
        return hex - '0';
    }
    else if (hex >= 'a' && hex <= 'f')
    {
        return hex - 'a' + 10;
    }
    else if (hex >= 'A' && hex <= 'F')
    {
        return hex - 'A' + 10;
    }
    perror("Invalid hex char");
    exit(EXIT_FAILURE);
}

void parse_to_int(char *hex, u64 *bignum)
{
    bignum[0] = 0;
    bignum[1] = hextoint(hex[5]) ^ hextoint(hex[4]) << 4 ^ hextoint(hex[3]) << 8 ^ hextoint(hex[2]) << 12 ^ hextoint(hex[1]) << 16 ^ hextoint(hex[0]) << 20;
    bignum[2] = hextoint(hex[13]) >> 3 ^ hextoint(hex[12]) << 1 ^ hextoint(hex[11]) << 5 ^ hextoint(hex[10]) << 9 ^ hextoint(hex[9]) << 13 ^ hextoint(hex[8]) << 17 ^ hextoint(hex[7]) << 21 ^ (hextoint(hex[6]) & 0xf) << 25;
    bignum[3] = hextoint(hex[20]) >> 2 ^ hextoint(hex[19]) << 2 ^ hextoint(hex[18]) << 6 ^ hextoint(hex[17]) << 10 ^ hextoint(hex[16]) << 14 ^ hextoint(hex[15]) << 18 ^ hextoint(hex[14]) << 22 ^ (hextoint(hex[13]) & 0x7) << 26;
    bignum[4] = hextoint(hex[27]) >> 1 ^ hextoint(hex[26]) << 3 ^ hextoint(hex[25]) << 7 ^ hextoint(hex[24]) << 11 ^ hextoint(hex[23]) << 15 ^ hextoint(hex[22]) << 19 ^ hextoint(hex[21]) << 23 ^ (hextoint(hex[20]) & 0x3) << 27;
    bignum[5] = hextoint(hex[34]) ^ hextoint(hex[33]) << 4 ^ hextoint(hex[32]) << 8 ^ hextoint(hex[31]) << 12 ^ hextoint(hex[30]) << 16 ^ hextoint(hex[29]) << 20 ^ hextoint(hex[28]) << 24 ^ (hextoint(hex[27]) & 0x1) << 28;
    bignum[6] = hextoint(hex[42]) >> 3 ^ hextoint(hex[41]) << 1 ^ hextoint(hex[40]) << 5 ^ hextoint(hex[39]) << 9 ^ hextoint(hex[38]) << 13 ^ hextoint(hex[37]) << 17 ^ hextoint(hex[36]) << 21 ^ (hextoint(hex[35]) & 0xf) << 25;
    bignum[7] = hextoint(hex[49]) >> 2 ^ hextoint(hex[48]) << 2 ^ hextoint(hex[47]) << 6 ^ hextoint(hex[46]) << 10 ^ hextoint(hex[45]) << 14 ^ hextoint(hex[44]) << 18 ^ hextoint(hex[43]) << 22 ^ (hextoint(hex[42]) & 0x7) << 26;
    bignum[8] = hextoint(hex[56]) >> 1 ^ hextoint(hex[55]) << 3 ^ hextoint(hex[54]) << 7 ^ hextoint(hex[53]) << 11 ^ hextoint(hex[52]) << 15 ^ hextoint(hex[51]) << 19 ^ hextoint(hex[50]) << 23 ^ (hextoint(hex[49]) & 0x3) << 27;
    bignum[9] = hextoint(hex[63]) ^ hextoint(hex[62]) << 4 ^ hextoint(hex[61]) << 8 ^ hextoint(hex[60]) << 12 ^ hextoint(hex[59]) << 16 ^ hextoint(hex[58]) << 20 ^ hextoint(hex[57]) << 24 ^ (hextoint(hex[56]) & 0x1) << 28;
}

void parse_to_hex(u64 *bignum, char *hex)
{
    u64 temp[4];
    temp[0] = bignum[3] >> 18 ^ bignum[2] << 11 ^ bignum[1] << 40;
    temp[1] = bignum[5] >> 12 ^ bignum[4] << 17 ^ bignum[3] << 46;
    temp[2] = bignum[7] >> 6 ^ bignum[6] << 23 ^ bignum[5] << 52;
    temp[3] = bignum[9] ^ bignum[8] << 29 ^ bignum[7] << 58;
    for (int i = 0; i < 4; i++)
        sprintf(hex + (i * 16), "%016llx", temp[i]);
    hex[64] = '\0';
}

void main()
{
    u64 poly[10];
    parse_to_int(t, poly);

    for (int i = 9; i >= 0; i--)
    {
        printf("%llx\n", poly[i]);
    }

    parse_to_hex(poly, )
}
