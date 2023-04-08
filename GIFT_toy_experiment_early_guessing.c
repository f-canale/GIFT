//Guessing Less and Better: Improved Attacks on GIFT-64
//Federico Canale (Ruhr University Bochum) and Maria Naya-Plasencia (INRIA)
//submitted to Design, Codes and Cryptography
//federico.canale at rub.de
//This code computes experimentally the number of triplets generated for the first key guessing on the GIFT-like toy cipher

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <sodium.h>
#include "toyGIFT.h"

#define ROUNDS 5
#define NumS (N/M)
#define RB 2
#define RF 0

void generate_table_values();
void prepare_attack_output();
int generate_guess(int current_sbox, int X[], int Xp[]);
int generate_trees( int N_G[], int N_S[]);
int convert_RK_to_GK( int RK[][2], int current_sbox, int WhereFrom);
int check_rank(int rowN, int mat[rowN]);
int print_GK();
int invalid_guess ();
int compute_next_Sbox(int current_sbox, int X[], int Xp[]);
int compute_Tree(int outputBit,  int current_sbox, int X[], int Xp[]);
int key_recovery( int p0, int p1, int p2, int p3, int pp0, int pp1, int pp2, int pp3);

int GK[1<<KL][KL+2];
int possible_values[(1<<M)*(1<<M)][(1<<M)+2];
int nabla[NumS*(RB+RF)][1<<M]={0};
int OBit[NumS*(RB+RF)];
int end_early_guess= 4;
int counter_guess[1<<KL];
int total_guess=1;
int current_guess=0;
int frequency_determined[1<<KL];
int total_guess_combined=0;

int main ()
{
   if (sodium_init() == -1)
   {
      printf("errorrrr");
   }

   printf("0x%x\n", enc(0x1,0,5));

   for (int i=0; i< (1<<KL); i++)
   {
      frequency_determined[i]=0;
   }

   generate_table_values();

   prepare_attack_output();

   int number_of_trials=(1<<20); // number of pairs used

   for (int trials=0; trials<number_of_trials; trials++)
   {
      // pi and ppi are randomly generated plaintext pairs
      unsigned int p0 = randombytes_random()%16;
      unsigned int p1 = randombytes_random()%16;
      unsigned int p2 = randombytes_random()%16;
      unsigned int p3 = randombytes_random()%16;
      unsigned int pp0 = randombytes_random()%16;
      unsigned int pp1 = randombytes_random()%16;
      unsigned int pp2 = randombytes_random()%16;
      unsigned int pp3 = randombytes_random()%16;

      total_guess_combined+=key_recovery(p0,p1,p2,p3,pp0,pp1,pp2,pp3);
   }

   printf("Total guess combined is %d. Average number of guess %f ", total_guess_combined, (float)total_guess_combined/(float)number_of_trials);


}

//key recovery launch. Prepares the vector GK that stores the possible guesses, the nabla and Obit that fixes the necessary information to determine
// (i.e. which output diff or values are possible). Finally, it prints the number of guessed keys and the (un)determined master keybits
int key_recovery( int p0, int p1, int p2, int p3, int pp0, int pp1, int pp2, int pp3)
{
   //prepare GK
   total_guess=1; //total number of guesses made thus far
   current_guess=0; //counter of the guess being examined

   //GK holds all the guesses of the keys (represented as subspaces. G[i] is made up of equations G[i][j]. An equation <\alpha, x>=b is represented as an integer G[i][j]= 2*alpha+b)
   for (int i=0; i< (1<<KL); i++)
   {
      for (int j=0; j<KL+2; j++)
      {
         GK[i][j]=0;
      }
      GK[i][KL]=0;
      GK[i][KL+1]=0;
   }

   GK[0][KL]=0; // the first guess is created in Sbox 0 always!

   for (int i=0; i< (1<<KL); i++)
   {
      counter_guess[i]=0;
   }

   // X[i] and Xp[i] hold the state values of an input plaintext after applying Sbox i
   int X[NumS*(RB+RF)];
   int Xp[NumS*(RB+RF)];

   for (int i=0; i < NumS*(RB+RF); i++)
   {
      X[i]=-1;
      Xp[i]=-1;
   }

   X[0]=p0;
   X[1]=p1;
   X[2]=p2;
   X[3]=p3;

   Xp[0]=pp0;
   Xp[1]=pp1;
   Xp[2]=pp2;
   Xp[3]=pp3;

   int current_sbox=0; //keeps track of the current sbox being analysed for generating the key guesses (e.g. current_sbox =4 is the first sbox of the second round)

   generate_guess( current_sbox, X, Xp);

   print_GK();

   if (total_guess!=0)
   {
      printf("pair is 0x%x, 0x%x (LSN 0x%x, 0x%x)\n", p0^(p1<<4)^(p2<<8)^(p3<<12), pp0^(pp1<<4)^(pp2<<8)^(pp3<<12), p0, pp0);

      printf("Guess counter:%d\n", total_guess);

      printf("frequency determined: ");
      for (int i=0; i<(1<<KL); i++)
      {
         if ( (frequency_determined[i]>0) || (i==0xc0) || (i ==0x3) )
         {
            printf("0x%x: %4d|| ", i, frequency_determined[i] );
         }
      }
      puts("");
   }

   return total_guess;
}

//Main recursive function to generate new guesses. Given the SBox current_sbox, it calls the relevant function to generate
//the guessed keys based on the possible output differences given by nabla[current_sbox] (uses trees if it is zero, possible_values if it is not)
int generate_guess(int current_sbox, int X[], int Xp[])
{
   int guess_before_sbox=current_guess; //number of guessed keys at the beginning of the analysis of the sbox
   int RK[2][2];
   RK[0][0]=0;
   RK[0][1]=0;
   RK[1][0]=0;
   RK[1][1]=0;

   int newX[NumS*(RB+RF)];
   int newXp[NumS*(RB+RF)];

   if (current_sbox>4)
   {
      return 1;
   }

   int i=0;
   int sigma = current_sbox % NumS; // sbox number within a round (e.g. sbox 4 is the first (0) sbox of the second round)
   int x= X[current_sbox];
   int xp= Xp[current_sbox];

   if ( x>15 || xp>15) // x and xp are always nibbles (4 bits)
   {
      exit(0);
   }

   while (nabla[current_sbox][i] != 0x1FFFF) // as long as current_sbox has output differences for which new guesses must be generated
   {
      int Delta= nabla[current_sbox][i];

      if (Delta == 0) // if the possible output difference being examined is zero, generate key guesses using trees
      {
         if (x == xp)
         {
            int outputBit=OBit[current_sbox];
            if ( compute_Tree(outputBit,  current_sbox, X, Xp) ==0 ) //On input X and Xp because newX and newXp will be created there
            {
               invalid_guess ();
               return 0;
            }
         }
      }
      else{ //if output difference is non-zero, use the pre-computed table possible_values to generate the possible key guesses
      int j=2;

      while ( possible_values[(x^xp)+16*Delta][j] !=0x1FFFF )
      {
         if ( x>15 || xp>15) // x and xp are always nibbles (4 bits)
         {
            exit(0);
         }
         int rk=possible_values[(x^xp)+16*Delta][j]^x; //possible values of the round keys
         if (rk==0 || rk==4 || rk==8 || rk== 0xc) //rk can only be an xor of two MSB bits. Cannot be any value
         {
            for (int i=0; i< NumS*(RB+RF); i++) //prepare newX, newXp since they will branch out to new guesses
            {
               newX[i]=X[i];
               newXp[i]=Xp[i];
            }

            newX[current_sbox]=S[x^rk];
            newXp[current_sbox]=S[xp^rk];
            RK[0][0]=1;
            RK[0][1]=(rk>>2)&1;
            RK[1][0]=2;
            RK[1][1]= (rk>>3)&1;

            if ( convert_RK_to_GK(RK,current_sbox, 0xd) )
            {
               compute_next_Sbox( current_sbox, newX, newXp); //prepares the state for generating the guess based on the next Sbox

               (current_guess)++;
               GK[current_guess][KL]=current_sbox;
               total_guess++;
            }
            else
            {
               invalid_guess();
               return 0;
            }
         }
         j++;

      }
   }

      i++;
   }

   //At the end of the analysis fo the sbox, check if a guess was generated for some possible output difference
   if (current_guess == guess_before_sbox)
   {
      invalid_guess();
   }
   // The current_guess will be updated after "compute nextsbox" resolves anyway (and was already updated by the previous call of compute tree or generate)
   else{
      current_guess--;
      total_guess--;
   }

   return 1;
}


//generates the recursive tree by updating the state for the next sbox and calling generate_guess
int compute_next_Sbox( int current_sbox, int X[], int Xp[])
{
   current_sbox++;
   int sigma=current_sbox%NumS;



   if (sigma==0)// Sbox must be computed
   {

      while (nabla[current_sbox][0] == 0x1FFF)
      {
         current_sbox++;
      } //if this Sbox is active, the relevant output bits were computed and we can compute the next round
      X[current_sbox]=0;
      Xp[current_sbox]=0;
      for (int i=0; i< M; i++)// This is 4=M
      {
         int temp= invP[sigma*M+i];
         int bit =temp%M;
         int sboxN= current_sbox - sigma- NumS+ temp/M; // current_sbox - sigma- NumS is the first sbox of the previous round. temp/4 is the number of the sbox%numS where invP is.


         X[current_sbox]^= ((X[sboxN]>>bit)&1)*(1<<i);
         Xp[current_sbox]^= ((Xp[sboxN]>>bit)&1)*(1<<i);

      }
   }


   generate_guess( current_sbox, X, Xp);

   return 1;
}

//Convert a round key guess to a master key guess by checking for consistency (not strictly necessary in this toy example)
int convert_RK_to_GK( int RK[][2], int current_sbox, int WhereFrom)
{
   for (int i=0; i<2; i++)
   {
      if ( RK[i][0] != 0 )
      {
         GK[current_guess][counter_guess[current_guess]]= RK[i][1]+(1<<( 1+ ((2*current_sbox)%KL) ) )*RK[i][0];


         int temp[counter_guess[current_guess]+1];
         for (int j=0; j< counter_guess[current_guess]+1; j++)
         {
            temp[j]=GK[current_guess][i];
         }
         int new_rank =check_rank(counter_guess[current_guess]+1, GK[current_guess]);

         if (new_rank==counter_guess[current_guess])
         {

            GK[current_guess][counter_guess[current_guess]]=0;
         }
         else if (new_rank==-1)
         {
            print_GK();
            invalid_guess ();
            return 0;
         }
         else
         {

            counter_guess[current_guess]++;
         }

      }
   }

   return 1;
}


// prepares the necessary information to do the keyguessing (i.e. which output differences or output values are needed to be determined for each sbox) and stores it in nabla and Obit.
void prepare_attack_output()
{
   for (int i=0; i < NumS*(RB+RF); i++)
   {
      OBit[i]=0x1FFFF;

      for (int j=0; j < (1<<M); j++)
      {
         nabla[i][j]=0x1FFFF;
      }
   }

   for (int i=0; i < 4; i++)
   {
      nabla[i][0]=0;
   }

   //nabla[i] are the possible output differences for Sbox i
   nabla[0][1] = 0x1;
   nabla[1][1] = 0x8;
   nabla[2][1] = 0x4;
   nabla[3][1] = 0x2;
   nabla[4][0] = 0x1;

   //Obit[i]=j if Output bit j is needed to be determined (e.g. with trees) for Sbox i
   OBit[0]=0;
   OBit[1]=3;
   OBit[2]=2;
   OBit[3]=1;


   for (int i=0; i < NumS*(RB+RF); i++)
   {

      int j=0;
      while (nabla[i][j] != 0x1FFFF)
      {

         j++;
      }


   }
}


int print_GK()
{
   int flag_invalid=0; // counts how many invalid guesses are stored in GK (they are signaled by the last entry of the array being -1)

   for (int i=0; i< total_guess+ flag_invalid; i++)
   {
      int smallest_guess=1+(2*GK[i][KL]%KL);

      if (GK[i][KL+1]==-1)
      {
         flag_invalid++;
      }

      for (int k=0; k< counter_guess[i-1]; k++)
      {
         if (GK[i-1][k]< ( 1<<(smallest_guess) ) )
         {
            GK[i][counter_guess[i]]=GK[i-1][k];
            counter_guess[i]++;
         }
      }

      int j = 0;
      while (GK[i][j]!=0 )
      {
          if (GK[i][KL+1]>=0)
          {
             frequency_determined[GK[i][j]>>1]++;
          }

          j++;
      }
   }
}

//when a guess is invalid, cancel it and decrease the number of total_guesses
int invalid_guess ()
{
   GK[current_guess][KL+1]=-1;

   total_guess--;
}

//generate the possible values that an input to an Sbox must have in order to satisfy a certain output difference
void generate_table_values()
{
   int counter[(1<<M)*(1<<M)]={0};

   //possible_values[16*i+j] is the set of possible input values for a pair of input difference j to have output difference i.
   //In other words, possible_values[16*i+j][k]=x if and only if S[x]^S[x^j]=i (unless x=0x1FFF which siganls the end of the set)
   for (int x = 0; x < (1<<M); x++)
   {
      for (int y = 0; y <(1<<M); y++)
      {
         possible_values[16*(S[x]^S[y])+x^y][0]=S[x]^S[y];
         possible_values[16*(S[x]^S[y])+x^y][1]=x^y;
         possible_values[16*(S[x]^S[y])+x^y][counter[16*(S[x]^S[y])+x^y]+2]=x;
         counter[16*(S[x]^S[y])+x^y]++;
      }
   }

   for (int i=0; i< (1<<M)*(1<<M); i++)
   {
      if ( counter[i]!=0)
      {
         for (int j=counter[i]+2; j< ((1<<M)+2); j++)
         {
            possible_values[i][j]=0x1FFFF;
         }

      }
      else
      {
         for (int j=0; j< ((1<<M)+2); j++)
         {
            possible_values[i][j]=0x1FFFF;
         }
      }
   }

}

int check_rank(int rowN, int mat[rowN])
{
   int zerocolumns=0; // counts the number of all-zero columns (the pivot, or 1, must be in the row c-zerocolumns)
   int max =0;

   for (int r=0; r < rowN; r++)
   {
      if (mat[r]>max)
      {
         max=mat[r];
      }
   }

   int maxCol=-1;
   do {
         maxCol++;
   } while ((max>>maxCol)!=0);


   for (int c=0; c < rowN; c++)
   {
      int isAllzero=1; //column is all zero? if yes 1.
      int nonzero;
      for (int r=c-zerocolumns; r< maxCol; r++) //look for a nonzero row and xor it to all other non-zero
      {


         if ( ((mat[r]>>(maxCol-c-1))&1) ==1 )
         {

            if (isAllzero==1)
            {
               isAllzero=0;
               nonzero=r;//row s.t. that has a 1 in column c (i.e. mat[nonzero][c] !=0)
               if ( (c-zerocolumns)!=nonzero) //if c is zero and the column is not all nonzero, then swap c and nonzero
               {
                  int temp=mat[c-zerocolumns];
                  mat[c-zerocolumns]=mat[nonzero];
                  mat[nonzero]=temp;
               }

            }
            else
            {
               mat[r]=mat[r]^mat[nonzero];
            }
         }
      }

      if (isAllzero==1) // if the column is all zero, update the number of zerocolumns
      {
         zerocolumns++;
      }

   }

   int rank=0;


   for (int i=0; i< rowN; i++)
   {

      if (mat[i]!=0)
      {
         if (mat[i]>>1==0)
         {
            return -1;
         }
         rank++;
      }
   }

   return rank;
}

// computes the necessary guess and output value based on the output bit that needs to be guessed (using trees). It also calls for the next Sbox to generate further guesses
int compute_Tree(int outputBit, int current_sbox, int X[], int Xp[])
{
   int RK[2][2];
   RK[0][0]=0;
   RK[0][1]=0;
   RK[1][0]=0;
   RK[1][1]=0;

   int newX[NumS*(RB+RF)];
   int newXp[NumS*(RB+RF)];


   int x= X[current_sbox];
   int x0= (x)&1;
   int x1= (x>>1)&1;
   int x2= (x>>2)&1;
   int x3= (x>>3)&1;

   int y;

   if ( x>15 )
   {

      exit(0);
   }

   if ( outputBit==0)
   {
      for (int guess=0; guess <2; guess++)
      {
         for (int i=0; i< NumS*(RB+RF); i++) //prepare newX, newXp since they will branch out to new guesses
         {
            newX[i]=X[i];
            newXp[i]=Xp[i];
         }
         if ( ( (x&3) == 0 ) || ( (x&3) == 2 ) )
         {
            y= ((x>>3)&1)^guess;
            RK[0][0]=2;
            RK[0][1]=guess;
            RK[1][0]=0;
            RK[1][1]=0;
         }

         if ( (x&3) == 1)
         {
            y= ((x>>3)&1)^((x>>2)&1)^guess;
            RK[0][0]=3;
            RK[0][1]=guess;
            RK[1][0]=0;
            RK[1][1]=0;
         }

         if ( (x&3) == 3 )
         {
            y= ((x>>2)&1)^guess;
            RK[0][0]=1;
            RK[0][1]=guess;
            RK[1][0]=0;
            RK[1][1]=0;
         }

         if (convert_RK_to_GK(RK, current_sbox, outputBit))
         {
            newX[current_sbox] = X[current_sbox]^(X[current_sbox]&(1<<outputBit))^(y*(1<<outputBit));
            newXp[current_sbox]= Xp[current_sbox]^(Xp[current_sbox]&(1<<outputBit))^(y*(1<<outputBit));

            compute_next_Sbox( current_sbox, newX, newXp);

            current_guess=current_guess+1;
            GK[current_guess][KL]=current_sbox;
            total_guess++;
         }
         else
         {
            return 0;
         }
      }
   }


   else if (outputBit==1)
   {
      for (int guess=0; guess <2; guess++)
      {
         for (int i=0; i< NumS*(RB+RF); i++) //prepare newX, newXp since they will branch out to new guesses
         {
            newX[i]=X[i];
            newXp[i]=Xp[i];
         }
         if ( (x&3) == 0  )
         {
            y= x1^x2^guess;
            RK[0][0]=1;
            RK[0][1]=guess;
            RK[1][0]=0;
            RK[1][1]=0;
         }

         if ( (x&3) == 1)
         {
            y= x3^guess^x1;
            RK[0][0]=2;
            RK[0][1]=guess;
            RK[1][0]=0;
            RK[1][1]=0;
         }

         if ( (x&3) == 2 )
         {
            y= x2^guess^x1;
            RK[0][0]=1;
            RK[0][1]=guess;
            RK[1][0]=0;
            RK[1][1]=0;
         }

         if ( (x&3) == 3 )
         {
            y= ((x>>3)&1)^((x>>2)&1)^guess^x1;
            RK[0][0]=3;
            RK[0][1]=guess;
            RK[1][0]=0;
            RK[1][1]=0;
         }

         if (convert_RK_to_GK(RK,  current_sbox, outputBit))
         {
            newX[current_sbox] = X[current_sbox]^(X[current_sbox]&(1<<outputBit))^(y*(1<<outputBit));
            newXp[current_sbox]= Xp[current_sbox]^(Xp[current_sbox]&(1<<outputBit))^(y*(1<<outputBit));

            compute_next_Sbox( current_sbox, newX, newXp);

            current_guess=current_guess+1;
            GK[current_guess][KL]=current_sbox;
            total_guess++;
         }
         else
         {
            return 0;
         }
      }
   }


   else if (outputBit==2)
   {
      for (int guess3=0; guess3 <2; guess3++)
      {
         if ((x3^guess3)==1)
         {
            for (int guess2=0; guess2<2; guess2++)
            {
               for (int i=0; i< NumS*(RB+RF); i++) //prepare newX, newXp since they will branch out to new guesses
               {
                  newX[i]=X[i];
                  newXp[i]=Xp[i];
               }
               y=x2^guess2^x0^1;
               RK[0][0]=1;
               RK[0][1]=guess2;
               RK[1][0]=2;
               RK[1][1]=guess3;

               if (convert_RK_to_GK(RK,  current_sbox, outputBit))
               {
                  newX[current_sbox] = X[current_sbox]^(X[current_sbox]&(1<<outputBit))^(y*(1<<outputBit));
                  newXp[current_sbox]= Xp[current_sbox]^(Xp[current_sbox]&(1<<outputBit))^(y*(1<<outputBit));

                  compute_next_Sbox( current_sbox, newX, newXp);

                  current_guess=current_guess+1;
                  GK[current_guess][KL]=current_sbox;
                  total_guess++;
               }
               else
               {
                  return 0;
               }
            }
         }
         else
         {
            for (int i=0; i< NumS*(RB+RF); i++) //prepare newX, newXp since they will branch out to new guesses
            {
               newX[i]=X[i];
               newXp[i]=Xp[i];
            }
            y= x1^x0;
            RK[0][0]=2;
            RK[0][1]=guess3;
            RK[1][0]=0;
            RK[1][1]=0;

            if (convert_RK_to_GK(RK,  current_sbox, outputBit))
            {
               newX[current_sbox] = X[current_sbox]^(X[current_sbox]&(1<<outputBit))^(y*(1<<outputBit));
               newXp[current_sbox]= Xp[current_sbox]^(Xp[current_sbox]&(1<<outputBit))^(y*(1<<outputBit));


               compute_next_Sbox( current_sbox, newX, newXp);
               current_guess=current_guess+1;
               GK[current_guess][KL]=current_sbox;
               total_guess++;
            }
            else
            {
               return 0;
            }
         }
      }
   }


   else if (outputBit==3)
   {
      for (int guess2=0; guess2 <2; guess2++)
      {
         if ((x2^guess2)==0)
         {
            for (int guess3=0; guess3<2; guess3++)
            {
               for (int i=0; i< NumS*(RB+RF); i++) //prepare newX, newXp since they will branch out to new guesses
               {
                  newX[i]=X[i];
                  newXp[i]=Xp[i];
               }
               y= x3^guess3^x1^x0^1;
               RK[0][0]=1;
               RK[0][1]=guess2;
               RK[1][0]=2;
               RK[1][1]=guess3;


               if (convert_RK_to_GK(RK,  current_sbox, outputBit))
               {
                  newX[current_sbox] = X[current_sbox]^(X[current_sbox]&(1<<outputBit))^(y*(1<<outputBit));
                  newXp[current_sbox]= Xp[current_sbox]^(Xp[current_sbox]&(1<<outputBit))^(y*(1<<outputBit));

                  compute_next_Sbox( current_sbox, newX, newXp);

                  current_guess=current_guess+1;
                  GK[current_guess][KL]=current_sbox;
                  total_guess++;
               }
               else
               {
                  return 0;
               }
            }
         }
         else
         {
            for (int i=0; i< NumS*(RB+RF); i++) //prepare newX, newXp since they will branch out to new guesses
            {
               newX[i]=X[i];
               newXp[i]=Xp[i];
            }
            y=x1^x0;
            RK[0][0]=1;
            RK[0][1]=guess2;
            RK[1][0]=0;
            RK[1][1]=0;

            if (convert_RK_to_GK(RK,  current_sbox, outputBit))
            {
               newX[current_sbox] = X[current_sbox]^(X[current_sbox]&(1<<outputBit))^(y*(1<<outputBit));
               newXp[current_sbox]= Xp[current_sbox]^(Xp[current_sbox]&(1<<outputBit))^(y*(1<<outputBit));

               compute_next_Sbox( current_sbox, newX, newXp);

               current_guess=current_guess+1;
               GK[current_guess][KL]=current_sbox;
               total_guess++;
            }
            else
            {
               return 0;
            }
         }
      }
   }
   return 1;
}
