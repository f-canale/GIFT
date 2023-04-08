//Guessing Less and Better: Improved Attacks on GIFT-64
//Federico Canale (Ruhr University Bochum) and Maria Naya-Plasencia (INRIA)
//submitted to Design, Codes and Cryptography
//federico.canale at rub.de
//This code was used to compute and generate the tables summarizing the pre-sieving probabilities and generated triplets of each Sbox type.

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define SIZE 16

char* utoa(unsigned int val, int base);

int sieve_probability( unsigned int goodpairs[], int goodpairs_size );
int possible_keys(  unsigned int goodpairs[], int goodpairs_size );


int main ()
{
    unsigned int x;
    unsigned int delta_in;
    unsigned int delta_out[SIZE]={0};
    //unsigned int S[SIZE]={6,5,0xC, 0xA, 1, 0xE, 7, 9, 0xB, 0, 3, 0xD, 8, 0xF, 4, 2};
    //unsigned int S[SIZE]={1,0xa,4,0xc,0x6,0xf,3,9,2,0xd,0xb,7,5,0,8,0xe};
    unsigned int S[SIZE]={8,4,6,0xa,2,0xd,0xc,1,5,0xb,0xf,0,3,0xe,9,7};
    //unsigned int invS[SIZE]={9,4, 0xF, 0xA, 0xE, 1, 0, 6, 0xC, 7, 3, 8, 2, 0xB, 5, 0xD};
    //unsigned int S[SIZE]={3,8,0xF, 1, 0xA,6, 5, 0xB, 0xE, 0xD,4, 2, 7, 0, 9, 0xC};
    //unsigned int S[SIZE]={8,4,6,0xa,2,0xd,0xc,1,5,0xb,0xf,0,3,0xe,9,7};

    int outvalues;
    unsigned int goodpairs_input[SIZE][SIZE] ={{0}}; //stores the good pairs with a given input difference for the selected output differences
    unsigned int goodpairs_input_size[SIZE] ={0}; //how many good pairs with a given input difference for the selected output differences
    int sieve[SIZE]={0}; //4*probability of sieving (it divides the number of pairs in groups of 4)
    float cost[SIZE]={0};

    float total_sieve=0;
    float total_cost=0;
    int inverse;

    printf("Press 0 for GIFT SBOX, 5 for INVERSE\n");
    scanf("%d", &inverse);

    if ( inverse == 0 )
    {
      for (int x=0; x < SIZE; x++)
      {
         printf("%3x", S[x]);
      }
      printf("\n");

    }
    else if (inverse == 5)
    {
      unsigned int tempS[SIZE]={0};

      for (int x =0; x < SIZE ; x++)
      {
         for (int y =0; y< SIZE; y++)
         {
            if ( S[y] == x )
            {
               tempS[x]=y;
            }
         }
      }

      for (int x=0; x < SIZE; x++)
      {
         S[x]=tempS[x];
         printf("%3x", S[x]);
      }
      printf("\n");

   }
   else
   {
      printf("wrong input\n");
      exit(1);
   }

    printf("How many output differences?\n");

    scanf("%d", &outvalues);

    printf("Enter the possible output difference(s)\n");


    for (int i=0; i < outvalues; i++)
    {
      scanf("%u", &delta_out[i]);
   }

   printf("\nYou have entered the following output differences:\n");


   for (int i=0; i < outvalues; i++)
   {
     printf("%3u", delta_out[i]);
   }
    
    //build all possible good pairs and store them in goodpairs_input; update good_pairs_input_size accordingly

    for ( delta_in=0; delta_in < 16; delta_in++ )
    {
      int firsttime=0;

            for (x = 0; x <16; x=x+1u )
            {
                int flag = 0;
                for (int j=0; j < outvalues; j++)
                {
                    if (delta_out[j] == (S[x]^S[x^delta_in] ) )
                        {
                           flag=1;
                        }
                }

                if ( flag==1 )
                {
                   if (firsttime==0)
                   {
                      unsigned int y=x^delta_in;
                      goodpairs_input[delta_in][goodpairs_input_size[delta_in]] = x;
                      goodpairs_input_size[delta_in]++;
                      firsttime=1;
                   }
                   else
                   {
                    unsigned int y=x^delta_in;
                    goodpairs_input[delta_in][goodpairs_input_size[delta_in]] = x;
                    goodpairs_input_size[delta_in]++;

                  }
                }
            }
    }

    printf("\ndelta_in, good values (sieve and cost). A good value x is such that (x,x+delta_in) is a good pair.\n\n");

   for ( delta_in=0; delta_in < SIZE; delta_in++ )
   {
      printf("%8u", delta_in);

            for (x = 0; x < goodpairs_input_size[delta_in]; x=x+1u )
            {
               printf("%3u", goodpairs_input[delta_in][x]);
            }

      sieve[delta_in]= sieve_probability(goodpairs_input[delta_in], goodpairs_input_size[delta_in]);

      if ( sieve[delta_in] != 0)
      {
         cost[delta_in]=(float)goodpairs_input_size[delta_in]/(sieve[delta_in]);
         total_cost+= (float)cost[delta_in]*(float)sieve[delta_in]/4;
      }
      else
      {
         cost[delta_in]=0;
      }

      total_sieve+= (float)sieve[delta_in]/4;

      printf("  sieve = %2d/4, cost = %2f \n", sieve[delta_in], cost[delta_in]);
   }

   printf("\nOverall sieving probability = %5f. \nOverall guessing cost (estimated) = %5f (no Key Abs).\n",total_sieve/SIZE, total_cost/total_sieve);
}


int sieve_probability( unsigned int goodpairs[], int goodpairs_size )
{
   unsigned int temp[SIZE] = {0};
   int counter=0; //counter of the different values of the first two bits (that go in temp)

   if ( goodpairs_size == 0) // if there are no good pairs, everything is sieved
   {
      return counter;
   }

   temp[counter]= ((goodpairs[0])&3);
   counter++;

   for ( int i =1; i< goodpairs_size; i++ )
   {
      int flag =1;
      for (int j = 0; j < counter; j++)
      {
         if (  ((goodpairs[i])&3) == temp[j] )
            {
               flag=0;
               //printf("(GP>>2)&3=%3u, temp=%3u, i=%3d, j=%3d, counter=%3d \n", ((goodpairs[i]>>2)&3), temp[j], i, j, counter);
               break;
            }
      }

      if (flag==1)
      {
         temp[counter]=(goodpairs[i])&3;
         //printf("GP=%3u, temp[%3d]=%3u, i=%3d, \n", goodpairs[i], counter, temp[counter], i);
         counter++;
      }
   }

   return counter; //how many possible values among the good pairs can the first two input take
}


int possible_keys(  unsigned int goodpairs[], int goodpairs_size )
{
   unsigned int temp[SIZE] = {0};
   int counter=0; //counter of the different values of the first two bits (that go in temp)

   if ( goodpairs_size == 0) // if there are no good pairs, everything is sieved
   {
      return counter;
   }

   temp[counter]= ((goodpairs[0]>>2)&3); //store first value of 2LSB bits in goodpairs
   counter++;

   for ( int i =1; i< goodpairs_size; i++ )
   {
      int flag =1;
      for (int j = 0; j < counter; j++)
      {
         if (  ((goodpairs[i]>>2)&3) == temp[j] )
            {
               flag=0;
               //printf("(GP>>2)&3=%3u, temp=%3u, i=%3d, j=%3d, counter=%3d \n", ((goodpairs[i]>>2)&3), temp[j], i, j, counter);
               break;
            }
      }

      if (flag==1)
      {
         temp[counter]=(goodpairs[i]>>2)&3;
         //printf("GP=%3u, temp[%3d]=%3u, i=%3d, \n", goodpairs[i], counter, temp[counter], i);
         counter++;
      }

   }
    
   return counter; //how many possible values among the good pairs can the first two input take
}
