
#ifndef AES_VITIS_H
#define AES_VITIS_H

#include <stdio.h>
#include <stdlib.h>
#include "ap_axi_sdata.h"
#include "hls_stream.h"

typedef ap_axiu<32,1,1,1> axi_data_t;

#define KEY_SIZE            16  // limiting encryption to AES-128 -> 16 byte key
#define EXPANDED_KEY_SIZE   176 // expanded key size = 11 keys x 16 bytes
#define BLOCK_SIZE          16  // an AES block is always 16 bytes
#define NUM_ROUNDS          10  // AES-128 has 10 rounds


/**************************************************
 *              Function Prototypes               *
 **************************************************/


// Key schedule functions and related helper functions

unsigned char getSBoxValue(int index);
unsigned char getRConValue(int index);
void rotate(unsigned char word[4]);
void core(unsigned char word[4], int iteration);
void expandKey(unsigned char expandedKey[EXPANDED_KEY_SIZE], const unsigned char key[KEY_SIZE]);

// AES round functions and helper functions

void subBytes(unsigned char state[BLOCK_SIZE]);
void shiftRows(unsigned char state[BLOCK_SIZE]);
void shiftRow(unsigned char state[BLOCK_SIZE], unsigned char nbr);
void addRoundKey(unsigned char state[BLOCK_SIZE], unsigned char roundKey[KEY_SIZE]);
unsigned char gmul(unsigned char a, unsigned char b);
void mixColumns(unsigned char state[BLOCK_SIZE]);
void mixColumn(unsigned char *column);
void aesRound(unsigned char state[BLOCK_SIZE], unsigned char roundKey[KEY_SIZE]);

void createRoundKey(unsigned char expandedKey[EXPANDED_KEY_SIZE], unsigned char roundKey[KEY_SIZE]);

// AES body and encryption functions
void aesMain(unsigned char state[BLOCK_SIZE], unsigned char expandedKey[EXPANDED_KEY_SIZE], int nbrRounds);
void aesEncryptTop(unsigned char input[BLOCK_SIZE], unsigned char output[BLOCK_SIZE], const unsigned char key[KEY_SIZE]);
void aesAXIWrapper(hls::stream<axi_data_t> &in, hls::stream<axi_data_t> &out);

#endif
