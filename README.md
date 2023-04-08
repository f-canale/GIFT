# Supplementary material for the GIFT attack

This is the supplementary material for the paper "Guessing Less and Better: Improved Attacks on GIFT-64".

## complexity_binomial.c 
Computes the average complexity of the merging phase for the guess of X24
## GIFT_toy_experiment_early_guessing.c
Computes experimentally the number of triplets/tuplets generated for the first key guessing on the GIFT-like toy cipher. Necessitates to be linked with the Sodium library
## GIFT_toy_experiment_presieving.c 
Computes experimentally the sieving probabilities for the second key guessing on the GIFT-like toy cipher. Necessitates to be linked with the Sodium library
## guess_gift.c 
Computes and generates the tables summarizing the pre-sieving probabilities and generated triplets/tuplets of each Sbox type.
