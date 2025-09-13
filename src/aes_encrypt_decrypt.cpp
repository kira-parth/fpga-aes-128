#include "aes_encrypt_decrypt.h"

// AES S-box for SubBytes operation
const uint8 sbox[256] = {
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

// Inverse S-box for InvSubBytes operation
const uint8 inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Round constant for key expansion
const uint8 Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Helper function: SubBytes transformation
void SubBytes(uint8 state[16]) {
    #pragma HLS INLINE
    for (int i = 0; i < 16; i++) {
        #pragma HLS UNROLL
        state[i] = sbox[state[i]];
    }
}

// Helper function: InvSubBytes transformation
void InvSubBytes(uint8 state[16]) {
    #pragma HLS INLINE
    for (int i = 0; i < 16; i++) {
        #pragma HLS UNROLL
        state[i] = inv_sbox[state[i]];
    }
}

// Helper function: ShiftRows transformation
void ShiftRows(uint8 state[16]) {
    #pragma HLS INLINE
    uint8 temp;
    
    // Row 1: shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // Row 2: shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift left by 3
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

// Helper function: InvShiftRows transformation
void InvShiftRows(uint8 state[16]) {
    #pragma HLS INLINE
    uint8 temp;
    
    // Row 1: shift right by 1
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    // Row 2: shift right by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift right by 3
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// Galois Field multiplication
uint8 xtime(uint8 x) {
    #pragma HLS INLINE
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

uint8 multiply(uint8 x, uint8 y) {
    #pragma HLS INLINE
    return (((y & 1) * x) ^
            ((y >> 1 & 1) * xtime(x)) ^
            ((y >> 2 & 1) * xtime(xtime(x))) ^
            ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
            ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

// Helper function: MixColumns transformation
void MixColumns(uint8 state[16]) {
    #pragma HLS INLINE
    uint8 tmp[16];
    #pragma HLS ARRAY_PARTITION variable=tmp complete
    
    for (int i = 0; i < 4; i++) {
        #pragma HLS UNROLL
        tmp[4*i] = multiply(0x02, state[4*i]) ^ multiply(0x03, state[4*i+1]) ^ state[4*i+2] ^ state[4*i+3];
        tmp[4*i+1] = state[4*i] ^ multiply(0x02, state[4*i+1]) ^ multiply(0x03, state[4*i+2]) ^ state[4*i+3];
        tmp[4*i+2] = state[4*i] ^ state[4*i+1] ^ multiply(0x02, state[4*i+2]) ^ multiply(0x03, state[4*i+3]);
        tmp[4*i+3] = multiply(0x03, state[4*i]) ^ state[4*i+1] ^ state[4*i+2] ^ multiply(0x02, state[4*i+3]);
    }
    
    for (int i = 0; i < 16; i++) {
        #pragma HLS UNROLL
        state[i] = tmp[i];
    }
}

// Helper function: InvMixColumns transformation
void InvMixColumns(uint8 state[16]) {
    #pragma HLS INLINE
    uint8 tmp[16];
    #pragma HLS ARRAY_PARTITION variable=tmp complete
    
    for (int i = 0; i < 4; i++) {
        #pragma HLS UNROLL
        tmp[4*i] = multiply(0x0e, state[4*i]) ^ multiply(0x0b, state[4*i+1]) ^ multiply(0x0d, state[4*i+2]) ^ multiply(0x09, state[4*i+3]);
        tmp[4*i+1] = multiply(0x09, state[4*i]) ^ multiply(0x0e, state[4*i+1]) ^ multiply(0x0b, state[4*i+2]) ^ multiply(0x0d, state[4*i+3]);
        tmp[4*i+2] = multiply(0x0d, state[4*i]) ^ multiply(0x09, state[4*i+1]) ^ multiply(0x0e, state[4*i+2]) ^ multiply(0x0b, state[4*i+3]);
        tmp[4*i+3] = multiply(0x0b, state[4*i]) ^ multiply(0x0d, state[4*i+1]) ^ multiply(0x09, state[4*i+2]) ^ multiply(0x0e, state[4*i+3]);
    }
    
    for (int i = 0; i < 16; i++) {
        #pragma HLS UNROLL
        state[i] = tmp[i];
    }
}

// Helper function: AddRoundKey transformation
void AddRoundKey(uint8 state[16], uint8 roundKey[16]) {
    #pragma HLS INLINE
    for (int i = 0; i < 16; i++) {
        #pragma HLS UNROLL
        state[i] ^= roundKey[i];
    }
}

// Key expansion function
void KeyExpansion(uint32 key[4], uint8 roundKeys[176]) {
    #pragma HLS INLINE
    uint8 temp[4];
    
    // Copy initial key
    for (int i = 0; i < 4; i++) {
        #pragma HLS UNROLL
        roundKeys[4*i] = key[i] >> 24;
        roundKeys[4*i+1] = (key[i] >> 16) & 0xFF;
        roundKeys[4*i+2] = (key[i] >> 8) & 0xFF;
        roundKeys[4*i+3] = key[i] & 0xFF;
    }
    
    // Generate round keys
    for (int i = 4; i < 44; i++) {
        #pragma HLS PIPELINE
        for (int j = 0; j < 4; j++) {
            temp[j] = roundKeys[(i-1)*4 + j];
        }
        
        if (i % 4 == 0) {
            // RotWord
            uint8 t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // SubWord
            for (int j = 0; j < 4; j++) {
                temp[j] = sbox[temp[j]];
            }
            
            temp[0] ^= Rcon[i/4];
        }
        
        for (int j = 0; j < 4; j++) {
            roundKeys[i*4 + j] = roundKeys[(i-4)*4 + j] ^ temp[j];
        }
    }
}

// AES block encryption
void AES_Encrypt_Block(uint8 input[16], uint8 output[16], uint8 roundKeys[176]) {
    #pragma HLS INLINE
    uint8 state[16];
    #pragma HLS ARRAY_PARTITION variable=state complete
    
    // Copy input to state
    for (int i = 0; i < 16; i++) {
        #pragma HLS UNROLL
        state[i] = input[i];
    }
    
    // Initial round
    AddRoundKey(state, roundKeys);
    
    // Main rounds
    for (int round = 1; round < 10; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, &roundKeys[round * 16]);
    }
    
    // Final round
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, &roundKeys[160]);
    
    // Copy state to output
    for (int i = 0; i < 16; i++) {
        #pragma HLS UNROLL
        output[i] = state[i];
    }
}

// AES block decryption
void AES_Decrypt_Block(uint8 input[16], uint8 output[16], uint8 roundKeys[176]) {
    #pragma HLS INLINE
    uint8 state[16];
    #pragma HLS ARRAY_PARTITION variable=state complete
    
    // Copy input to state
    for (int i = 0; i < 16; i++) {
        #pragma HLS UNROLL
        state[i] = input[i];
    }
    
    // Initial round
    AddRoundKey(state, &roundKeys[160]);
    
    // Main rounds
    for (int round = 9; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, &roundKeys[round * 16]);
        InvMixColumns(state);
    }
    
    // Final round
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);
    
    // Copy state to output
    for (int i = 0; i < 16; i++) {
        #pragma HLS UNROLL
        output[i] = state[i];
    }
}

// Main function
void aes_encrypt_decrypt(
    hls::stream<AXI_VALUE> &input_stream,
    hls::stream<AXI_VALUE> &output_stream,
    uint32 key[4],
    uint32 data_length,
    uint8 mode
) {
    #pragma HLS INTERFACE s_axilite port=key bundle=control
    #pragma HLS INTERFACE s_axilite port=data_length bundle=control
    #pragma HLS INTERFACE s_axilite port=mode bundle=control
    #pragma HLS INTERFACE axis port=input_stream
    #pragma HLS INTERFACE axis port=output_stream
    #pragma HLS INTERFACE s_axilite port=return bundle=control
    
    // Key expansion
    uint8 roundKeys[176];
    #pragma HLS ARRAY_PARTITION variable=roundKeys cyclic factor=16
    KeyExpansion(key, roundKeys);
    
    // Process data in 16-byte blocks
    uint32 num_blocks = (data_length + 15) / 16;
    
    for (uint32 block = 0; block < num_blocks; block++) {
        #pragma HLS PIPELINE II=16
        
        uint8 input_block[16];
        uint8 output_block[16];
        #pragma HLS ARRAY_PARTITION variable=input_block complete
        #pragma HLS ARRAY_PARTITION variable=output_block complete
        
        // Read 16 bytes from stream
        for (int i = 0; i < 16; i++) {
            #pragma HLS PIPELINE
            if ((block * 16 + i) < data_length) {
                AXI_VALUE temp = input_stream.read();
                input_block[i] = temp.data;
            } else {
                input_block[i] = 0; // Padding
            }
        }
        
        // Encrypt or decrypt block
        if (mode == 0) {
            AES_Encrypt_Block(input_block, output_block, roundKeys);
        } else {
            AES_Decrypt_Block(input_block, output_block, roundKeys);
        }
        
        // Write 16 bytes to stream
        for (int i = 0; i < 16; i++) {
            #pragma HLS PIPELINE
            AXI_VALUE temp;
            temp.data = output_block[i];
            temp.last = ((block == num_blocks - 1) && (i == 15)) ? 1 : 0;
            temp.keep = 1;
            temp.strb = 1;
            output_stream.write(temp);
        }
    }
}
