#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "crypto.h"
#include "ecc.h"
#include "nand.h"

#define NAND_ECC_OK 0 //From Bootmii MINI nand.h
#define NAND_ECC_CORRECTED 1
#define NAND_ECC_UNCORRECTABLE -1

static u8
    nand_cryptbuf[0x4000];

static int
    nand_fd
    = -1;

int nand_correct(u32 pageno, u8* data, u8* ecc)
{
    int uncorrectable = 0, corrected = 0;

    // get the correct ecc from spare data
    u32* ecc_read = (u32*)(ecc + 0x30);

    // compute the current ecc
    u32 ecc_calc[4];
    calc_ecc(data + 0x000, (u8*)&ecc_calc[0]);
    calc_ecc(data + 0x200, (u8*)&ecc_calc[1]);
    calc_ecc(data + 0x400, (u8*)&ecc_calc[2]);
    calc_ecc(data + 0x600, (u8*)&ecc_calc[3]);

    // correct corrupted data
    for (int i = 0; i < 4; i++) {
        // don't try to correct unformatted pages
        if (read32be((u8*)(ecc_read + i)) == 0xFFFFFFFF)
            continue;

        // calculate ecc syncrome
        u32 syndrome = read32be((u8*)(ecc_read + i)) ^ read32be((u8*)(ecc_calc + i));

        // no issues
        if (syndrome == 0)
            continue;

        // single-bit error in ECC
        if (((syndrome - 1) & syndrome) == 0) {
            corrected++;
            continue;
        }

        // byteswap and extract odd and even halves
        u16 even = (syndrome >> 24) | ((syndrome >> 8) & 0xf00);
        u16 odd = ((syndrome << 8) & 0xf00) | ((syndrome >> 8) & 0x0ff);

        // check if the error can be fixed
        if ((even ^ odd) == 0xfff) {
            // fix the bad bit
            data[(i * 0x200) + (odd >> 3)] ^= 1 << (odd & 7);
            corrected++;
        } else {
            // oops, can't fix this one
            uncorrectable++;
        }
    }

    if (uncorrectable || corrected)
        syslog(LOG_DEBUG, "ECC stats for NAND page 0x%X: %d uncorrectable, %d corrected\n", pageno, uncorrectable, corrected);
    if (uncorrectable)
        return NAND_ECC_UNCORRECTABLE;
    if (corrected)
        return NAND_ECC_CORRECTED;
    return NAND_ECC_OK;
}

int nand_read_sector(int sector, int num_sectors, u8* buffer, u8* ecc)
{
    int retval = NAND_ECC_OK;
    u8 buf[0x840];
    if (sector < 0 || num_sectors <= 0 || buffer == NULL)
        return NAND_ECC_OK;

    lseek(nand_fd, sector * 0x840, SEEK_SET);
    for (; num_sectors > 0; num_sectors--) {
        read(nand_fd, buffer, 0x800);
        if (ecc) {
            read(nand_fd, ecc, 0x40);
            memcpy(buf, buffer, 0x800);
            memcpy(&buf[0x800], ecc, 0x40);
            retval = nand_correct(sector, buffer, ecc);
            ecc += 0x40;
        } else {
            lseek(nand_fd, 0x40, SEEK_CUR);
        }
        buffer += 0x800;
        sector++;
    }
    return retval;
}

void nand_write_sector(int sector, int num_sectors, u8* buffer, u8* ecc)
{
    u8 null[0x40];
    if (sector < 0 || num_sectors <= 0 || buffer == NULL)
        return;
    memset(null, 0, 0x40);

    lseek(nand_fd, sector * 0x840, SEEK_SET);
    for (; num_sectors > 0; num_sectors--) {
        write(nand_fd, buffer, 0x800);
        if (ecc) {
            calc_ecc(buffer, ecc + 0x30);
            calc_ecc(buffer + 512, ecc + 0x30 + 4);
            calc_ecc(buffer + 1024, ecc + 0x30 + 8);
            calc_ecc(buffer + 1536, ecc + 0x30 + 12);
            write(nand_fd, ecc, 0x40);
            ecc += 0x40;
        } else {
            write(nand_fd, null, 0x40);
        }
        buffer += 0x800;
    }
}

int nand_read_cluster(int cluster_number, u8* cluster, u8* ecc)
{
    u8 eccbuf[0x200];
    int retval = nand_read_sector(cluster_number * 8, 8, cluster, eccbuf);
    if (ecc) {
        memcpy(ecc, &eccbuf[0x40 * 6], 0x40);
        memcpy(&ecc[0x40], &eccbuf[0x40 * 7], 0x40); //HMAC is in the 7th and 8th sectors.
    }
    return retval;
}

void nand_write_cluster(int cluster_number, u8* cluster, u8* hmac)
{
    u8 eccbuf[0x200];
    memset(eccbuf, 0, 0x200);
    if (hmac) {
        memcpy(&eccbuf[(0x40 * 6) + 1], hmac, 0x14);
        memcpy(&eccbuf[(0x40 * 6) + 0x15], hmac, 12);
        memcpy(&eccbuf[(0x40 * 7) + 1], &hmac[12], 8); //HMAC is in the 7th and 8th sectors.
    }
    nand_write_sector(cluster_number * 8, 8, cluster, eccbuf);
}

int nand_read_cluster_decrypted(int cluster_number, u8* cluster, u8* ecc)
{
    u8 iv[16];
    int retval;
    memset(iv, 0, 16);
    retval = nand_read_cluster(cluster_number, nand_cryptbuf, ecc);
    crypto_nand_aes_decrypt(iv, nand_cryptbuf, cluster, 0x4000);
    return retval;
}

void nand_write_cluster_encrypted(int cluster_number, u8* cluster, u8* ecc)
{
    u8 iv[16];
    memset(iv, 0, 16);
    crypto_nand_aes_encrypt(iv, cluster, nand_cryptbuf, 0x4000);
    nand_write_cluster(cluster_number, nand_cryptbuf, ecc);
}

int nand_init(char* nand_file)
{
    // open nand file
    nand_fd = open(nand_file, O_RDWR);

    if (nand_fd < 0) {
        printf("nand: failed to open %s\n", nand_file);
        return nand_fd;
    }

    return 0;
}

void nand_exit()
{
    if (nand_fd < 0)
        return;

    close(nand_fd);
    nand_fd = -1;
}
