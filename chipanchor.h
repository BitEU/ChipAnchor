/*
 * ChipAnchor: The Little UNIVAC AES Encryptor
 * AES-256-CBC Encryption
 *
 * Modern C implementation for Windows Console and UNIVAC
 * Portable implementation with platform-specific support
 */

#ifndef CHIPANCHOR_H
#define CHIPANCHOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

// Platform-specific includes
#ifndef UNIVAC
#include <windows.h>
#endif

// AES Constants
#define AES_BLOCK_SIZE 16      // 128-bit block size
#define AES_KEY_SIZE 32        // 256-bit key size (32 bytes)
#define AES_ROUNDS 14          // Number of rounds for AES-256
#define AES_NK 8               // Number of 32-bit words in key (256-bit)
#define AES_NB 4               // Number of columns (32-bit words) in state
#define MAX_KEY_INPUT 256

// AES State structure
typedef struct {
    uint8_t key[AES_KEY_SIZE];           // 256-bit encryption key
    uint8_t iv[AES_BLOCK_SIZE];          // Initialization vector for CBC
    uint8_t round_keys[AES_ROUNDS + 1][AES_NB][4];  // Expanded round keys
    uint8_t buffer[AES_BLOCK_SIZE];      // Buffer for incomplete blocks
    int buffer_len;                       // Current buffer length
    int initialized;                      // Whether encryption has started
} AESState;

// Function declarations

// Initialization
void init_aes(AESState* state);
void init_key(AESState* state);
void init_iv(AESState* state);

// Runtime configuration
void parse_arguments(int argc, char* argv[], AESState* state);
void interactive_config(AESState* state);
void set_key(AESState* state, const char* key_hex);
void set_iv(AESState* state, const char* iv_hex);
void print_usage(const char* program_name);
void print_current_config(const AESState* state);

// Main encryption loop
void run_aes(AESState* state);

// Helper functions
void hex_to_bytes(const uint8_t* hex_str, uint8_t* bytes, int num_bytes);
void bytes_to_hex(const uint8_t* bytes, char* hex_str, int num_bytes);
int is_hex_char(char c);

// AES Core functions
void key_expansion(AESState* state);
void add_round_key(uint8_t state_block[AES_NB][4], uint8_t round_key[AES_NB][4]);
void sub_bytes(uint8_t state_block[AES_NB][4]);
void shift_rows(uint8_t state_block[AES_NB][4]);
void mix_columns(uint8_t state_block[AES_NB][4]);
uint8_t gf_mul(uint8_t a, uint8_t b);
void aes_encrypt_block(uint8_t block[AES_BLOCK_SIZE], const AESState* state);

// CBC mode encryption
void encrypt_cbc(AESState* state, const uint8_t* input, uint8_t* output, int length);
void process_final_block(AESState* state);

// Platform-specific functions
#ifndef UNIVAC
void console_setup(void);
#endif

#endif // CHIPANCHOR_H
