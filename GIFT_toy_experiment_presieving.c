//Guessing Less and Better: Improved Attacks on GIFT-64
//Federico Canale (Ruhr University Bochum) and Maria Naya-Plasencia (INRIA)
//submitted to Design, Codes and Cryptography
//federico.canale at rub.de
//This code computes experimentally the sieving probabilities for the second key guessing on the GIFT-like toy cipher


#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <sodium.h>
#include "toyGIFT.h"

#define ROUNDS 5
#define NumS (N/M)
#define RB 2
#define RF 0

int key_recovery( int p0, int p1, int p2, int p3, int pp0, int pp1, int pp2, int pp3, int good_pairs2LSB[1<<M][1<<(M/2)]);
void create_goodpairs2LSB(int good_pairs2LSB[1<<M][1<<(M/2)]);



int main ()
{
   if (sodium_init() == -1)
   {
      printf("errorrrr");
   }

   printf("0x%x\n", enc(0x1,0,5));


   int total_triplets=0;
   int good_pairs2LSB[1<<M][1<<(M/2)];

   create_goodpairs2LSB(good_pairs2LSB);

   int number_of_trials=1<<20;

      for (int trials=0; trials<number_of_trials; trials++)
      {
         unsigned int p0 = randombytes_random()%16;
         unsigned int p1 = randombytes_random()%16;
         unsigned int p2 = randombytes_random()%16;
         unsigned int p3 = randombytes_random()%16;
         unsigned int pp0 = randombytes_random()%16;
         unsigned int pp1 = randombytes_random()%16;
         unsigned int pp2 = randombytes_random()%16;
         unsigned int pp3 = randombytes_random()%16;


         total_triplets+=key_recovery(p0,p1,p2,p3,pp0,pp1,pp2,pp3, good_pairs2LSB);
      }

        printf("Total triplets are %d. Average number of guess %f ", total_triplets, (float)total_triplets/(float)(number_of_trials*(1<<8)));

}



int key_recovery( int p0, int p1, int p2, int p3, int pp0, int pp1, int pp2, int pp3, int good_pairs2LSB[1<<M][1<<(M/2)])
{
   int counter=0;
   int y[4];
   int yp[4];
   int key=0;

   for ( key=0; key <(1<<8); key++)
   {
      //compute the output values
      y[0]=S[p0^((key&3)<<2)];
      yp[0]=S[pp0^((key&3)<<2)];
      y[1]=S[p1^((key&0xc))];
      yp[1]=S[pp1^((key&0xc))];
      y[2]=S[p2^((key&0x30)>>2)];
      yp[2]=S[pp2^((key&0x30)>>2)];
      y[3]=S[p3^((key&0xc0)>>4)];
      yp[3]=S[pp3^((key&0xc0)>>4)];

      int flag=0;
       
      //compute the output differences
      for (int i=0; i<4; i++)
      {
         int delta_in=y[i]^yp[i];
         int known_value=y[i]&3;

         if ( (good_pairs2LSB[delta_in][known_value]) ==1)
         {
            flag++;
         }
      }
      if (flag==4)
      {
         counter++;
      }
   }

   return counter;
}



void create_goodpairs2LSB( int good_pairs2LSB[1<<M][1<<(M/2)])
{
   for (int i=0; i< (1<<M); i++)
   {
      for (int j=0; j< (1<<(M/2)); j++)
      {
         good_pairs2LSB[i][j]=0;
      }
   }

   for ( int delta_in=0; delta_in < 16; delta_in++ )
   {
      for (int x = 0; x <16; x++ )
      {
         if ((S[x]^S[x^delta_in])==0xa)
         {
            int good2LSB= x&3;
            good_pairs2LSB[delta_in][good2LSB]=1;
            printf("delta_in 0x%x, x 0x%x, S[x]^S[x^delta_in]= 0x%x\n",delta_in, x, S[x]^S[x^delta_in]);
         }
      }
   }

   for (int i=0; i< (1<<M); i++)
   {
      printf("Difference %d:", i);

      for (int j=0; j< (1<<(M/2)); j++)
      {
         if (good_pairs2LSB[i][j]==1)
         {
            printf("%d", j);
         }
      }
      puts("");
   }
}
