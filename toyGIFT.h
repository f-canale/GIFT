//Guessing Less and Better: Improved Attacks on GIFT-64
//Federico Canale (Ruhr University Bochum) and Maria Naya-Plasencia (INRIA)
//submitted to Design, Codes and Cryptography
//federico.canale at rub.de
//This is the implementation of toyGIFT

#include <stdint.h>


#define M 4
#define N 16
#define KL 16
#define unit64 (uint64_t)1

int key_add(int input, int round_key);
uint64_t permutation(uint64_t input);
int enc(int input, uint64_t key, int rounds);
uint64_t extract_bits(uint64_t input, unsigned int start, unsigned int end);
uint64_t rol(uint64_t num, unsigned int shift, int size);
uint64_t Slayer( uint64_t input );


unsigned int S[1<<M]={8,4,6,0xa,2,0xd,0xc,1,5,0xb,0xf,0,3,0xe,9,7};
int P[N]={0,5,10,15,4,9,14,3,8,13,2,6,12,1,7,11};
int invP[N]={0,13,10,7,4,1,11,14,8,5,2,15,12,9,6,3};

uint64_t rol(uint64_t num, unsigned int shift, int size)
{
    uint64_t output = (num << shift) ^ (num >> (size - shift));
    output= output & ((unit64<<size)-1);

    return output;
}


uint64_t permutation(uint64_t input)
{

    uint64_t output=0;

    for ( int i =0; i < N; i++)
    {
        if ( ((input >>i) &1) ==  1 )
        {
            output^= (unit64<< P[i]);
        }
    }

    return output;
}


int key_add(int input, int round_key)
{
    return input ^ round_key;
}


uint64_t Slayer( uint64_t input )
{
    uint64_t temp_in =input;
    uint64_t output=0;

    for (int i=0; i < N/M; i++)
    {
        output^=(S[temp_in&0xF]<<((M)*i));

        temp_in=temp_in>>(M);
    }

    return output;
}


int enc(int input, uint64_t key, int rounds)
{
    int ct = input;

    for (int i =0; i< rounds; i++)
    {
        ct = Slayer(ct);
        printf("round %d > %x \n", i, ct);
        ct= permutation(ct);
    }


    return ct;
}
