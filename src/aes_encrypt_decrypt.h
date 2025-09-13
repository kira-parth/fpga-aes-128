#ifndef AES_ENCRYPT_DECRYPT_H
#define AES_ENCRYPT_DECRYPT_H

#include <ap_int.h>
#include <hls_stream.h>
#include <ap_axi_sdata.h>

// Type definitions
typedef ap_uint<8> uint8;
typedef ap_uint<32> uint32;
typedef ap_uint<128> uint128;

// AXI Stream packet structure
typedef ap_axiu<8, 0, 0, 0> AXI_VALUE;

// Top function prototype
void aes_encrypt_decrypt(
    hls::stream<AXI_VALUE> &input_stream,
    hls::stream<AXI_VALUE> &output_stream,
    uint32 key[4],           // 128-bit key as 4x32-bit words
    uint32 data_length,      // Number of bytes to process
    uint8 mode              // 0: encrypt, 1: decrypt
);

#endif
