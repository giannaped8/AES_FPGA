
/* *********************************************
 *      Testbench Code for AES Encryption      *
 * ******************************************* *
 * includes 2 tests:                           *
 *                                             *
 * Test A tests the aes_encrypt_top function   *
 * for encryption correctness.                 *
 *                                             *
 * Test B tests the aes_axi_wrapper function   *
 * for proper data transmission between the    *
 * REST API and the IP block.                  *
 *                                             *
 *       ONLY 1 TEST CAN RUN AT A TIME         *
 ***********************************************/

#include "aes_vitis.h"

// UNCOMMENT THE FOLLOWING LINES TO TEST AES_ENCRYPT_TOP
// TEST A START:
// int main(int argc, char *argv[]) {
//     printf("Test bench starting...\n");
//     unsigned char key[KEY_SIZE] = {'t', 'h', 'i', 's', 'i', 's', 'a', 'k', 'e', 'y', '1', '2', '3', '4', '5', '6'};
//     unsigned char plaintext[BLOCK_SIZE] = {'a', 'e', 's', 't', 'e', 's', 't', 'm', 'i', 'l', 'e', 's', 't', 'o', 'n', 'e'};
//     unsigned char ciphertext[BLOCK_SIZE];
    
//     // AES Encryption
//     aes_encrypt_top(plaintext, ciphertext, key);

//     printf("\nCiphertext (HEX format):\n");
//     for (int i = 0; i < BLOCK_SIZE; i++) {
//         printf("%2.2x%c", ciphertext[i], ((i + 1) % BLOCK_SIZE) ? ' ' : '\n');
//     }

//     return 0;
// }
// TEST A END

// UNCOMMENT THE FOLLOWING LINES TO TEST AES_AXI_WRAPPER
// TEST B START:
int main() {
    // Create input and output HLS streams for axi_data_t
    hls::stream<axi_data_t> inData("inData");
    hls::stream<axi_data_t> outData("outData");

    //plaintext = "aestestmilestone"
    ap_uint<128> plaintext = ap_uint<128>("616573746573746D696C6573746F6E65", 16);

    // Create an axi_data_t element for input
    // Create 4 packets. For each 32-bit word, extract 32 bits from the 128-bit plaintext
    for (int i = 0; i < 4; i++) {
        axi_data_t inElem;
        // For big-endian reassembly, shift right by 32*(3-i) bits so that the desired word lands
        // in the low 32 bits, then mask off the rest
        ap_uint<32> word = (plaintext >> (32 * (3 - i))) & 0xFFFFFFFF;
        inElem.data = word;
    
        // Print the extracted 32-bit word
        printf("Input packet %d 32-bit word: 0x%08x\n", i, (unsigned)word);
        
        inElem.last = (i == 3) ? 1 : 0;
        inElem.keep = -1;
        inElem.strb = -1;
        inElem.id = 0;
        inElem.dest = 0;
        inElem.user = 0;
    
        inData.write(inElem);
    }
    // Call the AES HLS wrapper function
    // This function will read one axi_data_t from the inData stream, process it, and write one axi_data_t to the outData stream
    aesAXIWrapper(inData, outData);

    ap_uint<128> cipherVal = 0;

    for (int i = 0; i < 4; i++) {
        axi_data_t outElem = outData.read();
        // Print the TLAST signal for each word
        printf("Output word &d TLAST: %u, 0x%08x\n", i, (unsigned)outElem.last, (unsigned) outElem.data);
        // Assemble the ciphertext.
        cipherVal = (cipherVal << 32) | outElem.data;
    }
    // Print out the encrypted data
    unsigned long long high = (unsigned long long)(cipherVal >> 64);
    unsigned long long low  = (unsigned long long) cipherVal;
    printf("Encrypted data (hex): 0x%016llx%016llx\n", high, low);
    
    return 0;
}
// TEST B END
