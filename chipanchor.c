/*
 * Program Name: ChipAnchor
 * Program Release Year: 2025
 * Program Author: Steven S.
 * Program Link: https://github.com/BitEU/ChipAnchor
 * Purpose: A simple AES-256-CBC encrytor with Windows Console/UNIVAC 1219 support
 */

#include "chipanchor.h"

// Platform-specific string copy
#ifdef UNIVAC
#define SAFE_STRCPY(dest, src, size) do { strncpy(dest, src, (size)-1); (dest)[(size)-1] = '\0'; } while(0)
#else
#define SAFE_STRCPY(dest, src, size) strcpy_s(dest, size, src)
#endif

// AES S-box (Substitution box)
static const uint8_t sbox[256] = {
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
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES Round constant for key expansion
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Main entry point
int main(int argc, char* argv[]) {
#ifndef UNIVAC
    console_setup();
#endif

    AESState state;
    init_aes(&state);

    // If no command-line arguments, use interactive configuration
    if (argc == 1) {
        interactive_config(&state);
    } else {
        // Parse command-line arguments for runtime configuration
        parse_arguments(argc, argv, &state);
    }

    run_aes(&state);

    return 0;
}

// Initialize AES state
void init_aes(AESState* state) {
    // BSS initialization - zero out entire state structure
    memset(state, 0, sizeof(AESState));

    // Initialize with default key (all zeros)
    init_key(state);

    // Initialize with default IV (all zeros)
    init_iv(state);

    state->buffer_len = 0;
    state->initialized = 0;
}

// Initialize key with default (zeros)
void init_key(AESState* state) {
    memset(state->key, 0, AES_KEY_SIZE);
}

// Initialize IV with default (zeros)
void init_iv(AESState* state) {
    memset(state->iv, 0, AES_BLOCK_SIZE);
}

// Helper: Convert hex string to bytes
void hex_to_bytes(const uint8_t* hex_str, uint8_t* bytes, int num_bytes) {
    for (int i = 0; i < num_bytes; i++) {
        char high = hex_str[i * 2];
        char low = hex_str[i * 2 + 1];
        
        // Convert hex characters to nibbles
        uint8_t high_nibble = (high >= '0' && high <= '9') ? (high - '0') :
                              (high >= 'A' && high <= 'F') ? (high - 'A' + 10) :
                              (high >= 'a' && high <= 'f') ? (high - 'a' + 10) : 0;
        
        uint8_t low_nibble = (low >= '0' && low <= '9') ? (low - '0') :
                             (low >= 'A' && low <= 'F') ? (low - 'A' + 10) :
                             (low >= 'a' && low <= 'f') ? (low - 'a' + 10) : 0;
        
        bytes[i] = (high_nibble << 4) | low_nibble;
    }
}

// Helper: Convert bytes to hex string
void bytes_to_hex(const uint8_t* bytes, char* hex_str, int num_bytes) {
    const char hex_chars[] = "0123456789ABCDEF";
    for (int i = 0; i < num_bytes; i++) {
        hex_str[i * 2] = hex_chars[bytes[i] >> 4];
        hex_str[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex_str[num_bytes * 2] = '\0';
}

// Helper: Check if character is valid hex
int is_hex_char(char c) {
    return (c >= '0' && c <= '9') || 
           (c >= 'A' && c <= 'F') || 
           (c >= 'a' && c <= 'f');
}

// Galois Field multiplication
uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        uint8_t hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1b; // AES polynomial
        }
        b >>= 1;
    }
    return p;
}

// AES Key Expansion
void key_expansion(AESState* state) {
    uint8_t temp[4];
    int i = 0;
    
    // Copy the initial key into the first round keys
    for (i = 0; i < AES_NK; i++) {
        state->round_keys[i / AES_NB][i % AES_NB][0] = state->key[4 * i];
        state->round_keys[i / AES_NB][i % AES_NB][1] = state->key[4 * i + 1];
        state->round_keys[i / AES_NB][i % AES_NB][2] = state->key[4 * i + 2];
        state->round_keys[i / AES_NB][i % AES_NB][3] = state->key[4 * i + 3];
    }
    
    // Generate the remaining round keys
    for (i = AES_NK; i < AES_NB * (AES_ROUNDS + 1); i++) {
        int k = (i - 1) / AES_NB;
        int l = (i - 1) % AES_NB;
        
        temp[0] = state->round_keys[k][l][0];
        temp[1] = state->round_keys[k][l][1];
        temp[2] = state->round_keys[k][l][2];
        temp[3] = state->round_keys[k][l][3];
        
        if (i % AES_NK == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // SubWord
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            
            temp[0] ^= rcon[i / AES_NK];
        } else if (AES_NK > 6 && i % AES_NK == 4) {
            // SubWord for AES-256
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }
        
        k = (i - AES_NK) / AES_NB;
        l = (i - AES_NK) % AES_NB;
        
        int new_k = i / AES_NB;
        int new_l = i % AES_NB;
        
        state->round_keys[new_k][new_l][0] = state->round_keys[k][l][0] ^ temp[0];
        state->round_keys[new_k][new_l][1] = state->round_keys[k][l][1] ^ temp[1];
        state->round_keys[new_k][new_l][2] = state->round_keys[k][l][2] ^ temp[2];
        state->round_keys[new_k][new_l][3] = state->round_keys[k][l][3] ^ temp[3];
    }
}

// Add Round Key transformation
void add_round_key(uint8_t state_block[AES_NB][4], uint8_t round_key[AES_NB][4]) {
    for (int i = 0; i < AES_NB; i++) {
        for (int j = 0; j < 4; j++) {
            state_block[i][j] ^= round_key[i][j];
        }
    }
}

// SubBytes transformation
void sub_bytes(uint8_t state_block[AES_NB][4]) {
    for (int i = 0; i < AES_NB; i++) {
        for (int j = 0; j < 4; j++) {
            state_block[i][j] = sbox[state_block[i][j]];
        }
    }
}

// ShiftRows transformation
void shift_rows(uint8_t state_block[AES_NB][4]) {
    uint8_t temp;
    
    // Row 1: shift left by 1
    temp = state_block[0][1];
    state_block[0][1] = state_block[1][1];
    state_block[1][1] = state_block[2][1];
    state_block[2][1] = state_block[3][1];
    state_block[3][1] = temp;
    
    // Row 2: shift left by 2
    temp = state_block[0][2];
    state_block[0][2] = state_block[2][2];
    state_block[2][2] = temp;
    temp = state_block[1][2];
    state_block[1][2] = state_block[3][2];
    state_block[3][2] = temp;
    
    // Row 3: shift left by 3 (or right by 1)
    temp = state_block[3][3];
    state_block[3][3] = state_block[2][3];
    state_block[2][3] = state_block[1][3];
    state_block[1][3] = state_block[0][3];
    state_block[0][3] = temp;
}

// MixColumns transformation
void mix_columns(uint8_t state_block[AES_NB][4]) {
    for (int i = 0; i < AES_NB; i++) {
        uint8_t a[4];
        a[0] = state_block[i][0];
        a[1] = state_block[i][1];
        a[2] = state_block[i][2];
        a[3] = state_block[i][3];
        
        state_block[i][0] = gf_mul(a[0], 2) ^ gf_mul(a[1], 3) ^ a[2] ^ a[3];
        state_block[i][1] = a[0] ^ gf_mul(a[1], 2) ^ gf_mul(a[2], 3) ^ a[3];
        state_block[i][2] = a[0] ^ a[1] ^ gf_mul(a[2], 2) ^ gf_mul(a[3], 3);
        state_block[i][3] = gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ gf_mul(a[3], 2);
    }
}

// Encrypt a single 16-byte block
void aes_encrypt_block(uint8_t block[AES_BLOCK_SIZE], const AESState* state) {
    uint8_t state_block[AES_NB][4];
    
    // Copy input block to state (column-major order)
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state_block[i][j] = block[i * 4 + j];
        }
    }
    
    // Initial round key addition
    add_round_key(state_block, (uint8_t(*)[4])state->round_keys[0]);
    
    // Main rounds
    for (int round = 1; round < AES_ROUNDS; round++) {
        sub_bytes(state_block);
        shift_rows(state_block);
        mix_columns(state_block);
        add_round_key(state_block, (uint8_t(*)[4])state->round_keys[round]);
    }
    
    // Final round (no MixColumns)
    sub_bytes(state_block);
    shift_rows(state_block);
    add_round_key(state_block, (uint8_t(*)[4])state->round_keys[AES_ROUNDS]);
    
    // Copy state back to output block
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            block[i * 4 + j] = state_block[i][j];
        }
    }
}

// Encrypt data in CBC mode
void encrypt_cbc(AESState* state, const uint8_t* input, uint8_t* output, int length) {
    uint8_t block[AES_BLOCK_SIZE];
    
    for (int i = 0; i < length; i += AES_BLOCK_SIZE) {
        // XOR with previous ciphertext (or IV for first block)
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            block[j] = input[i + j] ^ state->iv[j];
        }
        
        // Encrypt block
        aes_encrypt_block(block, state);
        
        // Copy to output and update IV
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            output[i + j] = block[j];
            state->iv[j] = block[j];
        }
    }
}

// Process final block with PKCS7 padding
void process_final_block(AESState* state) {
    if (state->buffer_len > 0 || state->initialized) {
        // Apply PKCS7 padding
        uint8_t padding = AES_BLOCK_SIZE - state->buffer_len;
        for (int i = state->buffer_len; i < AES_BLOCK_SIZE; i++) {
            state->buffer[i] = padding;
        }
        
        uint8_t output[AES_BLOCK_SIZE];
        encrypt_cbc(state, state->buffer, output, AES_BLOCK_SIZE);
        
        // Output as hex
        char hex_output[AES_BLOCK_SIZE * 2 + 1];
        bytes_to_hex(output, hex_output, AES_BLOCK_SIZE);
        printf("%s", hex_output);
        fflush(stdout);  // Flush output immediately
    }
}

// Main encryption loop
void run_aes(AESState* state) {
    int c;
    
    // Expand the key before encryption
    key_expansion(state);
    
    while ((c = getchar()) != EOF) {
        state->initialized = 1;
        state->buffer[state->buffer_len++] = (uint8_t)c;
        
        // When buffer is full, encrypt and output
        if (state->buffer_len == AES_BLOCK_SIZE) {
            uint8_t output[AES_BLOCK_SIZE];
            encrypt_cbc(state, state->buffer, output, AES_BLOCK_SIZE);
            
            // Output as hex
            char hex_output[AES_BLOCK_SIZE * 2 + 1];
            bytes_to_hex(output, hex_output, AES_BLOCK_SIZE);
            printf("%s", hex_output);
            fflush(stdout);  // Flush output immediately
            
            state->buffer_len = 0;
        }
    }
    
    // Process final block with padding
    process_final_block(state);
    printf("\n");
}

// Runtime configuration functions

// Interactive configuration (for teletype/terminal use)
void interactive_config(AESState* state) {
    char input[MAX_KEY_INPUT];

    printf("CHIPANCHOR: THE LITTLE UNIVAC AES ENCRYPTOR\n");
    printf("AES-256-CBC ENCRYPTION\n");
    printf("\n");
    printf("--- CONFIGURATION ---\n");
    printf("\n");

    // Get encryption key
    printf("ENCRYPTION KEY (64 HEX CHARS FOR 256-BIT, PRESS ENTER FOR DEFAULT): ");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) != NULL) {
        // Remove newline
        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n') {
            input[len - 1] = '\0';
            len--;
        }

        // Trim whitespace
        char* start = input;
        while (*start == ' ' || *start == '\t') start++;

        if (*start != '\0' && len > 0) {
            set_key(state, start);
            printf("KEY SET\n");
        } else {
            printf("USING DEFAULT KEY (ALL ZEROS)\n");
        }
    }

    printf("\n");

    // Get IV
    printf("INITIALIZATION VECTOR (32 HEX CHARS, PRESS ENTER FOR DEFAULT): ");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) != NULL) {
        // Remove newline
        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n') {
            input[len - 1] = '\0';
            len--;
        }

        // Trim whitespace
        char* start = input;
        while (*start == ' ' || *start == '\t') start++;

        if (*start != '\0' && len > 0) {
            set_iv(state, start);
            printf("IV SET\n");
        } else {
            printf("USING DEFAULT IV (ALL ZEROS)\n");
        }
    }

    printf("\n");
    printf("--- READY TO ENCRYPT ---\n");
    printf("ENTER DATA (CTRL+Z OR CTRL+D TO END):\n");
    printf("OUTPUT WILL BE HEX ENCODED\n");
    printf("\n");
    fflush(stdout);
}

// Print usage information
void print_usage(const char* program_name) {
    fprintf(stderr, "ChipAnchor: The Little UNIVAC AES Encryptor\n");
    fprintf(stderr, "Usage: %s [OPTIONS]\n\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -k KEY          Set encryption key (64 hex characters for 256-bit)\n");
    fprintf(stderr, "                  Example: -k 0123456789ABCDEF...\n");
    fprintf(stderr, "  -i IV           Set initialization vector (32 hex characters)\n");
    fprintf(stderr, "                  Example: -i 0123456789ABCDEF...\n");
    fprintf(stderr, "  -s              Show current configuration and exit\n");
    fprintf(stderr, "  -h              Show this help message\n\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s -k 00112233...FF                    # Encrypt with custom key\n", program_name);
    fprintf(stderr, "  echo \"SECRET\" | %s -k KEY -i IV        # Encrypt with key and IV\n\n", program_name);
    fprintf(stderr, "Encryption: AES-256-CBC | Output: Hex encoded\n");
}

// Print current configuration
void print_current_config(const AESState* state) {
    char key_hex[AES_KEY_SIZE * 2 + 1];
    char iv_hex[AES_BLOCK_SIZE * 2 + 1];
    
    bytes_to_hex(state->key, key_hex, AES_KEY_SIZE);
    bytes_to_hex(state->iv, iv_hex, AES_BLOCK_SIZE);

    fprintf(stderr, "=== ChipAnchor Configuration ===\n");
    fprintf(stderr, "Algorithm:  AES-256-CBC\n");
    fprintf(stderr, "Key:        %s\n", key_hex);
    fprintf(stderr, "IV:         %s\n", iv_hex);
    fprintf(stderr, "================================\n");
}

// Set encryption key from hex string
void set_key(AESState* state, const char* key_hex) {
    if (!key_hex) {
        fprintf(stderr, "Error: Key cannot be NULL\n");
        exit(1);
    }
    
    size_t len = strlen(key_hex);
    if (len != AES_KEY_SIZE * 2) {
        fprintf(stderr, "Error: Key must be exactly %d hex characters (got %zu)\n", 
                AES_KEY_SIZE * 2, len);
        exit(1);
    }
    
    // Validate hex characters
    for (size_t i = 0; i < len; i++) {
        if (!is_hex_char(key_hex[i])) {
            fprintf(stderr, "Error: Invalid hex character '%c' in key\n", key_hex[i]);
            exit(1);
        }
    }
    
    hex_to_bytes((const uint8_t*)key_hex, state->key, AES_KEY_SIZE);
}

// Set initialization vector from hex string
void set_iv(AESState* state, const char* iv_hex) {
    if (!iv_hex) {
        fprintf(stderr, "Error: IV cannot be NULL\n");
        exit(1);
    }
    
    size_t len = strlen(iv_hex);
    if (len != AES_BLOCK_SIZE * 2) {
        fprintf(stderr, "Error: IV must be exactly %d hex characters (got %zu)\n", 
                AES_BLOCK_SIZE * 2, len);
        exit(1);
    }
    
    // Validate hex characters
    for (size_t i = 0; i < len; i++) {
        if (!is_hex_char(iv_hex[i])) {
            fprintf(stderr, "Error: Invalid hex character '%c' in IV\n", iv_hex[i]);
            exit(1);
        }
    }
    
    hex_to_bytes((const uint8_t*)iv_hex, state->iv, AES_BLOCK_SIZE);
}

// Parse command-line arguments
void parse_arguments(int argc, char* argv[], AESState* state) {
    int show_config = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        }
        else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--show") == 0) {
            show_config = 1;
        }
        else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -k requires an argument (64 hex characters)\n");
                print_usage(argv[0]);
                exit(1);
            }
            set_key(state, argv[++i]);
        }
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--iv") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -i requires an argument (32 hex characters)\n");
                print_usage(argv[0]);
                exit(1);
            }
            set_iv(state, argv[++i]);
        }
        else {
            fprintf(stderr, "Error: Unknown option '%s'\n\n", argv[i]);
            print_usage(argv[0]);
            exit(1);
        }
    }

    if (show_config) {
        print_current_config(state);
        exit(0);
    }
}

// Platform-specific console setup (Windows only)
#ifndef UNIVAC
void console_setup(void) {
    // Set console to UTF-8 for better text handling
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
}
#endif
