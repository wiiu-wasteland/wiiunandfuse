#include <openssl/aes.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "crypto.h"

static unsigned char
    crypto_nand_hmac[20];

static unsigned char
    crypto_nand_key[16];

static AES_KEY
    crypto_nand_enc,
    crypto_nand_dec;

/*
 * otp functions
 */

static int otp_fd = -1;

void otp_read(u32 index, void* buf, u32 size)
{
    lseek(otp_fd, index * 4, SEEK_SET);
    read(otp_fd, buf, size);
}

int otp_init(char* otp_file)
{
    otp_fd = open(otp_file, O_RDONLY);

    if (otp_fd < 0) {
        printf("otp: failed to open %s\n", otp_file);
        return otp_fd;
    }

    return 0;
}

void otp_exit()
{
    if (otp_fd < 0)
        return;

    close(otp_fd);
    otp_fd = -1;
}

/*
 * hmac
 * reversing done by gray
 */

void hmac_init(hmac_ctx* ctx, const unsigned char* key, int key_size)
{
    int i;

    key_size = key_size < 0x40 ? key_size : 0x40;

    memset(ctx->key, 0, 0x40);
    memcpy(ctx->key, key, key_size);

    for (i = 0; i < 0x40; ++i)
        ctx->key[i] ^= 0x36; // ipad

    SHA1_Init(&ctx->hash_ctx);
    SHA1_Update(&ctx->hash_ctx, ctx->key, 0x40);
}

void hmac_update(hmac_ctx* ctx, const void* data, int size)
{
    SHA1_Update(&ctx->hash_ctx, data, size);
}

void hmac_final(hmac_ctx* ctx, unsigned char* hmac)
{
    int i;
    unsigned char hash[0x14];

    SHA1_Final(hash, &ctx->hash_ctx);

    for (i = 0; i < 0x40; ++i)
        ctx->key[i] ^= 0x36 ^ 0x5c; // opad

    SHA1_Init(&ctx->hash_ctx);
    SHA1_Update(&ctx->hash_ctx, ctx->key, 0x40);
    SHA1_Update(&ctx->hash_ctx, hash, 0x14);

    SHA1_Final(hmac, &ctx->hash_ctx);
}

/*
 * nand crypto functions
 */

void crypto_nand_hmac_meta(const void* super_data, short super_blk, unsigned char* hmac)
{
    hmac_ctx ctx;
    unsigned char extra[0x40];

    memset(extra, 0, 0x40);
    write16be(extra + 0x12, super_blk);

    hmac_init(&ctx, crypto_nand_hmac, sizeof(crypto_nand_hmac));
    hmac_update(&ctx, extra, sizeof(extra));
    hmac_update(&ctx, super_data, 0x40000);
    hmac_final(&ctx, hmac);
}

void crypto_nand_hmac_data(const void* data, int uid, const char* name, int entry_n, int x3, short blk, unsigned char* hmac)
{
    hmac_ctx ctx;
    unsigned char extra[0x40];

    memset(extra, 0, 0x40);

    write32be(extra, uid);

    memcpy(extra + 4, name, 12);

    write16be(extra + 0x12, blk);
    write32be(extra + 0x14, entry_n);
    write32be(extra + 0x18, x3);

    hmac_init(&ctx, crypto_nand_hmac, sizeof(crypto_nand_hmac));
    hmac_update(&ctx, extra, 0x40);
    hmac_update(&ctx, data, 0x4000);
    hmac_final(&ctx, hmac);
}

void crypto_nand_aes_decrypt(u8* iv, u8* inbuf, u8* outbuf, unsigned long long len)
{
    AES_cbc_encrypt(inbuf, outbuf, len, &crypto_nand_dec, iv, AES_DECRYPT);
}

void crypto_nand_aes_encrypt(u8* iv, u8* inbuf, u8* outbuf, unsigned long long len)
{
    AES_cbc_encrypt(inbuf, outbuf, len, &crypto_nand_enc, iv, AES_ENCRYPT);
}

/*
 * initialize crypto for wii/wiiu
 */

void crypto_init(int version)
{
    memset(crypto_nand_hmac, 0, sizeof(crypto_nand_hmac));
    memset(crypto_nand_key, 0, sizeof(crypto_nand_key));

    switch (version) {
    case 0:
        otp_read(0x11, crypto_nand_hmac, 20);
        otp_read(0x16, crypto_nand_key, 16);
        break;
    case 1:
        otp_read(0x78, crypto_nand_hmac, 20);
        otp_read(0x5C, crypto_nand_key, 16);
        break;
    default:
        break;
    }

    AES_set_encrypt_key(crypto_nand_key, 128, &crypto_nand_enc);
    AES_set_decrypt_key(crypto_nand_key, 128, &crypto_nand_dec);
}
