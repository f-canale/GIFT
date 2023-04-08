//Guessing Less and Better: Improved Attacks on GIFT-64
//Federico Canale (Ruhr University Bochum) and Maria Naya-Plasencia (INRIA)
//submitted to Design, Codes and Cryptography
//federico.canale at rub.de
//This code was used to compute the average complexity of the merging phase for the guess of X24/Z24 using 


#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define SIZE 16
#define N 12
#define POW2N 4096



float int_to_prob ( int number );
int int_table_1 ( int number );
int int_table_2 ( int number );
int int_relations ( int number );
int compute_cost ( int number );

int bin_number[N];


float probabilities[N]= {1.0f/3.0f, 1.0f/3.0f, 1.0f/3.0f, 1.0f/7.0f, 1.0f/3.0f, 1.0f/3.0f, 1.0f/3.0f, 1.0f/7.0f, 5.0f/11.0f, 5.0f/11.0f, 5.0f/11.0f, 5.0f/11.0f}; //probabily of undetermination of nibbles 13, 16, 6 (round 0), 16 (round 1),  1, 5, 13 (round 0), 10 (round 1), 4, 11, 8, 15 (round 0). The first four are only involved in the guessing of table 1, the other four only in the guessing of table 2, the last four can be involved in either

int main ()
{
    int weight=0;
    float prob =0;
    float cost=0;
    int costarray[N+1]={0};
    //int costarray[N+1]={1,2,4,8,16,32,64,128,256,512,1024,2048,4096};

    float avg_keybitstoguess=24;
    float keybits_guessed=0;
    costarray[0]=2;
    
    for ( int i = 0; i < POW2N; i++ )
    {
        weight= int_table_1(i);
        prob=int_to_prob(i);
        //cost+=(float)costarray[weight]*prob;
        
        int temp_cost=compute_cost(i);
        cost+=(float)temp_cost*prob;
        keybits_guessed=(float)(int_table_1(i)+ int_table_2(i)-int_relations(i));
        avg_keybitstoguess+= prob*keybits_guessed;
        
        printf("i =%5d, table_1_bits = %5d, table_2_bits = %5d, relations=%5d, prob=%5f, cost = %5d, keybitsguessed in total =%5d\n", i, int_table_1(i), int_table_2(i), int_relations(i), prob, temp_cost, 24+int_table_1(i)+ int_table_2(i)-int_relations(i));
        
        
    }

    puts("");
    
    printf("Expected cost is %5f, expected number of keybits guessed (in total) is %5f\n", (float)cost, avg_keybitstoguess);
    
}

float int_to_prob ( int number )
{
    float prob=1;
    
    int counter =0;
    while ( number > 0 )
    {
        if ( number %2==1 )
        {
            prob=prob*probabilities[N-1-counter];
            printf(" %6f ", probabilities[N-1-counter]);
            
            number=(number-1)/2;
        }
        else
        {
            prob=prob*(1-probabilities[N-1-counter]);
            printf(" %6f ", 1-probabilities[N-1-counter]);

            number=number/2;
        }
        counter++;
    }
    
    while ( counter < N )
    {
        prob=prob*(1-probabilities[N-1-counter]);
        printf(" %6f ", 1-probabilities[N-1-counter]);

        counter++;
    }
    
    puts("");
    
    return prob;
}

int int_table_1 ( int number )
{
    int weight=0;
    int flag=0;
    
    int counter =0;
    while ( number > 0 )
    {
        if ( number %2==1 && counter < 4 ) // if there is a 1 in the 2 Sboxes of type 4 involved in building table 1, add a key guess in 5
        {
            weight++;
            
            if ( counter == 0 ) // if there is a 1 in sbox 8 (type 4), i.e. key absorption of 74 (1) and 104 (2)
            {
                flag=1;
            }
            
        }
       
        if ( number %2==1 && counter >=4 && counter < 8 ) //for all type 5 and type 1, add a keyguess
        {
            weight++;
        }
        
        if ( number %2==1 && counter == 4 && flag==1) //if type 6 sbox is determined, the bit is still to be guessed but we will have a linear relation (counted in int_rel), but the guess was already counted because keyabsorption is done for counter=0, and therefore the unkown bit coming from that sbox and belongs to this group/table is 74, so that one doesn't have to count it twice
        {
            weight--;
        }
        counter++;
        number=number/2;
    }
    
    return weight;
}


int int_table_2 ( int number )
{
    int weight=0;
    int flag=0;
    
    int counter =0;
    while ( number > 0 )
    {
        
        if ( number %2==1 && counter < 4 )
        {
            weight++;
            
            if ( counter == 1 ) // if there is a one in sbox 15 (type 4), i.e. key absorption
            {
                flag=1;
            }
        }
        
        if ( number %2==1 && counter >= 8  )
        {
            weight++;
        }
        
        if ( number %2==1 && counter == 8  ) //if type 6 sbox ... is undetermined, then the bit is still to be guessed but we will have a linear relation (counted in int_rel)
        {
            weight--;
        }
        
        counter++;
        number=number/2;

    }
    
    return weight;
}

int int_relations ( int number )
{
    int weight=0;
    int flag1=0;
    int flag2=0;
    
    int counter =0;
    while ( number > 0 )
    {
        if ( number %2 == 1 && (counter < 4))
        {
            weight++;
            
            if ( counter ==0 ) // if there is a one in sbox 8 (type 4), i.e. key absorption
            {
                flag1=1;
            }
            else if (counter == 1) // if there is a one in sbox 15 (type 4), i.e. key absorption
            {
                flag2=1;
            }
        }
        
        if ( number %2 == 1 && counter == 4 && flag1==1 )  // if there is a one in sbox 0 (type 4), i.e. key absorption happened, but type6 of sbox , k1 is not determined or guessed
        {
            weight--;
        }
        
        if ( number %2 == 1 && counter == 8 && flag2==1 ) // if there is a one in sbox 0 (type 4), i.e. key absorption happened, but type6 of sbox , k1 is not determined or guessed
        {
            weight--;
        }
        counter++;
        number=number/2;

    }
    
    return weight;
}


int compute_cost ( int number )

{
    int K1 = int_table_1(number);
    int K2 = int_table_2(number);
    int R = int_relations(number);
    int T1=4;
    int T2=4;
    
    if ( K1+K2 <=10)
    {
        T1=3;
        T2=3;
    }
    
    int cost = pow(2, K2+2.09*T1)+pow(2,K1+2.13*T2)+pow(2, K1+K2-R +12-(T1)*0.91-T2*0.87); //pow(2, K2- 8+ T2+2.09*T1)+pow(2,K1-8+T1+2.09*T2)+pow(2, K1+K2-R +12-16+(T1+T2)-(16-T1-T2)*0.91);

    return cost;
}

