#pragma once
#include <openssl/aes.h>
#include <openssl/sha.h>
#include "tools.h"

/* otp */
void otp_read(u32 index, void* buf, u32 size);
int otp_init(char* otp_file);
void otp_exit();

/* hmac */
typedef struct {
    unsigned char key[0x40];
    SHA_CTX hash_ctx;
} hmac_ctx;

void hmac_init(hmac_ctx* ctx, const unsigned char* key, int key_size);
void hmac_update(hmac_ctx* ctx, const void* data, int size);
void hmac_final(hmac_ctx* ctx, unsigned char* hmac);

/* nand crypto */
void crypto_init(int version);
void crypto_nand_hmac_meta(const void* super_data, short super_blk, unsigned char* hmac);
void crypto_nand_hmac_data(const void* data, int uid, const char* name, int entry_n, int x3, short blk, unsigned char* hmac);
void crypto_nand_aes_decrypt(u8* iv, u8* inbuf, u8* outbuf, unsigned long long len);
void crypto_nand_aes_encrypt(u8* iv, u8* inbuf, u8* outbuf, unsigned long long len);
