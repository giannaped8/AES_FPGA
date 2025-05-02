
#include "aes_vitis.h"

// SBox for the subBytes step (256 bytes total)
static const unsigned char SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};


// Round Constant (RCON) array for the key expansion (40 bytes total)
static const unsigned char RCON[40] = {
    0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00,
    0x1B, 0x00, 0x00, 0x00,
    0x36, 0x00, 0x00, 0x00};

// The 16-byte key
static const unsigned char KEY_BYTES[KEY_SIZE] = {
    't','h','i','s','i','s','a','k',
    'e','y','1','2','3','4','5','6'
};

//------------------------------------------------
//             Function Implementations
//------------------------------------------------

/* returns the SBOX value at index index*/
inline unsigned char getSBoxValue(int index) {
    return SBOX[index];
}

/* returns the RCON value at index index*/
unsigned char getRConValue(int index) {
    return RCON[index * 4];
}

/* the key schedule rotate operation
 * rotates the word eight bits to the left
 * word is a char array of size 4 (32 bit)
 */
void rotate(unsigned char word[4]) {
    unsigned char temp = word[0];

    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

/* the core operation of key expansion
 * rotates the word and does SBOX substitution on each byte
 * word is a char array of size 4 (32 bit)
 * iteration is which iteration the core is in for getRConValue
 */
void core(unsigned char word[4], int iteration) {
    // rotate the 32-bit word 8 bits to the left
    rotate(word);
    
    // apply S-Box substitution on all 4 parts of the 32-bit word
    for (int i = 0; i < 4; ++i) {
        #pragma HLS UNROLL
        word[i] = getSBoxValue(word[i]);
    }
    
    // XOR the output of the rcon operation with i to the first part (leftmost) only
    word[0] = word[0] ^ getRConValue(iteration);
}

/* the key expansion algorithm
 * expands the 128 bit key into a 176 byte key
 */
void expandKey(unsigned char expandedKey[EXPANDED_KEY_SIZE], const unsigned char key[KEY_SIZE]) {
    // current expanded keySize, in bytes
    int currentSize = 0;
    int rconIteration = 0;
    unsigned char t[4]; // temporary 4-byte variable
    #pragma HLS ARRAY_PARTITION variable=t complete

    // copy the original key into the first 4 words of the expanded key
    for (int i = 0; i < KEY_SIZE; i++) {
        #pragma HLS UNROLL
        expandedKey[i] = key[i];
    }
    currentSize += KEY_SIZE;

    while (currentSize < EXPANDED_KEY_SIZE) {
        // copy the last 4 bytes from the expanded key into temporary variable t
        for (int i = 0; i < 4; i++) {
            #pragma HLS UNROLL
            t[i] = expandedKey[(currentSize - 4) + i];
        }

        // every 16 bytes, apply the core schedule to t and increment rconIteration afterwards
        if (currentSize % KEY_SIZE == 0) {
            core(t, rconIteration++);
        }

        // XOR t with the word that is 16 bytes before the new expanded key
        // this becomes the next four bytes in the expanded key
        for (int i = 0; i < 4; i++) {
            #pragma HLS UNROLL
            expandedKey[currentSize + i] = expandedKey[currentSize - KEY_SIZE + i] ^ t[i];
        }
        currentSize+=4;
    }
}

/* the subbytes step
 * takes the state array and substitutes each byte with the corresponding SBOX value
 * state is a char array of size 16 (128 bit)
 */
void subBytes(unsigned char state[BLOCK_SIZE]) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        #pragma HLS UNROLL
        state[i] = getSBoxValue(state[i]);
    }
}

/* the shiftrows step
 * takes the state array and shifts each row to the left by the row number
 * state is a char array of size 16 (128 bit)
 */
void shiftRows(unsigned char state[BLOCK_SIZE]) {
    // row 0 is not shifted, so begin with row 1
    for (int i = 1; i < 4; i++) {
        #pragma HLS UNROLL
        shiftRow(state + i * 4, i);
    }
}

/* the shiftrows helper function
 * takes a row of the state array and shifts each row to the left by the row number
 * state is a char array of size 4 (32 bit)
 * shiftValue is the number of shifts to the left for the rows
 */
void shiftRow(unsigned char state[4], unsigned char shiftValue) {
    unsigned char temp[4];

    #pragma HLS ARRAY_PARTITION variable=temp complete
    
    // each iteration shifts the row to the left by 1
    for (int i = 0; i < 4; i++) {
        #pragma HLS UNROLL
            temp[i] = state[i];
    }

    for (int j = 0; j < 4; j++) {
        #pragma HLS UNROLL
        state[j] = temp[(j + shiftValue) % 4];
    }
}

/* the addroundkey step
 * takes the state array and XORs it with the roundKey for the given round
 * state is a char array of size 16 (128 bit)
 * roundKey is a char array of size 16 (128 bit)
 */
void addRoundKey(unsigned char state[BLOCK_SIZE], unsigned char roundKey[KEY_SIZE]) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        #pragma HLS UNROLL
        state[i] = state[i] ^ roundKey[i];
    }
}

/* the galois multiplication operation
 * multiplies two bytes in the galois field
 * a is the first byte
 * b is the second byte
 */
unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    for (unsigned char counter = 0; counter < 8; counter++) {
        if ((b & 1) == 1) {
            p ^= a;
        }
        unsigned char hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80) {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    return p;
}

/* the mixcolumns step
 * takes the state array and multiplies each column by a fixed matrix in the galois field
 * state is a char array of size 16 (128 bit)
 */
void mixColumns(unsigned char state[BLOCK_SIZE]) {
    unsigned char column[4];

    // iterate over the 4 columns
    for (int i = 0; i < 4; i++) {
        #pragma HLS UNROLL
        // construct one column by iterating over the 4 rows
        for (int j = 0; j < 4; j++) {
            #pragma HLS UNROLL
            column[j] = state[(j * 4) + i];
        }

        // apply the mixColumn on one column
        mixColumn(column);
        // put the values back into the state
        for (int j = 0; j < 4; j++) {
            #pragma HLS UNROLL
            state[(j * 4) + i] = column[j];
        }
    }  
}

/* the mixcolumn helper function
 * takes a column of the state array and multiplies it by a fixed matrix in the galois field
 * column is a char array of size 4 (32 bit)
 */
void mixColumn(unsigned char *column) {
    unsigned char copy[4];
    
    for (int i = 0; i < 4; i++) {
        #pragma HLS UNROLL
        copy[i] = column[i];
    }

    column[0] = gmul(copy[0], 2) ^ gmul(copy[3], 1) ^ gmul(copy[2], 1) ^ gmul(copy[1], 3);
    column[1] = gmul(copy[1], 2) ^ gmul(copy[0], 1) ^ gmul(copy[3], 1) ^ gmul(copy[2], 3);
    column[2] = gmul(copy[2], 2) ^ gmul(copy[1], 1) ^ gmul(copy[0], 1) ^ gmul(copy[3], 3);
    column[3] = gmul(copy[3], 2) ^ gmul(copy[2], 1) ^ gmul(copy[1], 1) ^ gmul(copy[0], 3);
}

/* the aes round function
 * applies the subBytes, shiftRows, mixColumns, and addRoundKey steps to the state array
 * state is a char array of size 16 (128 bit)
 * roundKey is a char array of size 16 (128 bit)
 */
void aesRound(unsigned char state[BLOCK_SIZE], unsigned char roundKey[KEY_SIZE]) {
    #pragma HLS ARRAY_PARTITION variable=state complete

    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, roundKey);
}

/* the createRoundKey function
 * separates the expandedKey into a roundKey for the given round
 * expandedKey is a char array of size 176 (1408 bit)
 * roundKey is a char array of size 16 (128 bit)
 */
void createRoundKey(unsigned char expandedKey[EXPANDED_KEY_SIZE], unsigned char roundKey[KEY_SIZE]) {
    for (int i = 0; i < 4; i++) {
        #pragma HLS UNROLL
        for (int j = 0; j < 4; j++) {
            #pragma HLS UNROLL
            roundKey[(i + (j * 4))] = expandedKey[(i * 4) + j];
        }
    }
}

/* the main aes function
 * applies the AES algorithm to the state array using the expandedKey
 * state is a char array of size 16 (128 bit)
 * expandedKey is a char array of size 176 (1408 bit)
 * numRounds is the number of rounds to apply
 */
void aesMain(unsigned char state[BLOCK_SIZE], unsigned char expandedKey[EXPANDED_KEY_SIZE], int numRounds) {
    unsigned char roundKey[BLOCK_SIZE];

    #pragma HLS ARRAY_PARTITION variable=roundKey complete

    // initial AddRoundKey step
    createRoundKey(expandedKey, roundKey);

    addRoundKey(state, roundKey);
    
    // rounds 1 - 9 (or numRounds-1)
    for (int i = 1; i < numRounds; i++) {
        createRoundKey(expandedKey + BLOCK_SIZE * i, roundKey);
        aesRound(state, roundKey);
    }
    // final round (Round 10 for AES-128) which excludes mixColumns
    createRoundKey(expandedKey + BLOCK_SIZE * numRounds, roundKey);
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKey);
}

/* the aes encryption function
 * encrypts the input array using the key and stores the result in the output array
 * input is a char array of size 16 (128 bit)
 * output is a char array of size 16 (128 bit)
 * key is a char array of size 16 (128 bit)
 * keySize is the size of the key in bytes
 */
void aesEncryptTop(unsigned char input[BLOCK_SIZE], unsigned char output[BLOCK_SIZE], const unsigned char key[KEY_SIZE]) {
    unsigned char expandedKey[EXPANDED_KEY_SIZE];
    unsigned char block[BLOCK_SIZE];

    #pragma HLS ARRAY_PARTITION variable=expandedKey complete
    #pragma HLS ARRAY_PARTITION variable=block complete
    #pragma HLS ARRAY_PARTITION variable=SBOX complete

    // map input into a 16-byte block (using column-major order)
    for (int i = 0; i < 4; i++) {
        #pragma HLS UNROLL
        for (int j = 0; j < 4; j++) {
            #pragma HLS UNROLL
            block[(i + (j * 4))] = input[(i * 4) + j];
        }
    }
    
    // expand the key into a 176 byte key
    expandKey(expandedKey, key);
    
    // encrypt the block using the expandedKey
    aesMain(block, expandedKey, NUM_ROUNDS);

    // map the block to the output
    for (int i = 0; i < 4; i++) {
        #pragma HLS UNROLL
        for (int j = 0; j < 4; j++) {
            #pragma HLS UNROLL
            output[(i * 4) + j] = block[(i + (j * 4))];
        }
    }
}

/* the AXI wrapper function for encryption
 * handles the data streams for communication between
 * the microprocessor and FPGA
 * in is a stream of type axi_data_t (32 bits)
 * out is a stream of type axi_data_t (32 bits)
 */
void aesAXIWrapper(hls::stream<axi_data_t> &in, hls::stream<axi_data_t> &out) {
    #pragma HLS INTERFACE axis port=in
    #pragma HLS INTERFACE axis port=out
    #pragma HLS INTERFACE s_axilite port=return bundle=CTRL
    #pragma HLS INTERFACE ap_ctrl_none port=return

    // variables for internal data storage
    axi_data_t inData, outData;
    unsigned char inBlock[BLOCK_SIZE];
    unsigned char outBlock[BLOCK_SIZE];
    
    bool lastFlags[4];

    #pragma HLS ARRAY_PARTITION variable=inBlock  complete
    #pragma HLS ARRAY_PARTITION variable=outBlock complete
    #pragma HLS ARRAY_PARTITION variable=lastFlags complete
    
    // index for reading the data
    int index = 0;

    // data read
    while(!in.empty()) {
        in.read(inData);
        // if the full block hasn't been read, add data to in_block
        if (index < 4) {
            ap_uint<32> word = inData.data;
            for (int i = 0; i < 4; ++i) {
                #pragma HLS UNROLL
                inBlock[index*4 + i] = (word >> (8 * (3-i))) & 0xFF;
            }
            // store the TLAST flags
            lastFlags[index] = inData.last;
            index++;
        }        
        // a whole block has been read
        if (index == 4) {

            aesEncryptTop(inBlock, outBlock, KEY_BYTES);            
            // reset index for next block
            index = 0;

            // map the ciphertext to the out stream
            for (int i = 0; i < 4; i++) {
                #pragma HLS UNROLL
                ap_uint<32> wordOut = 0;
                for (int j = 0; j < 4; j++) {
                    #pragma HLS UNROLL
                    wordOut |= ((ap_uint<32>)outBlock[i*4 + j]) << (8 * (3-j));
                }

                // send the encrypted message out to the stream
                outData.data = wordOut;
                // set the TLAST signal to 1 iff we are on the last loop iteration
                outData.last = lastFlags[i];
                outData.keep = inData.keep;
                outData.strb = inData.strb;
                outData.id   = inData.id;
                outData.dest = inData.dest;
                outData.user = inData.user;
                out.write(outData);
             }
        }
    }
}