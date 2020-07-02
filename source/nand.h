#pragma once
#include "tools.h"

int nand_correct(u32 pageno, u8* data, u8* ecc);

int nand_read_sector(int sector, int num_sectors, u8* buffer, u8* ecc);
void nand_write_sector(int sector, int num_sectors, u8* buffer, u8* ecc);

int nand_read_cluster(int cluster_number, u8* cluster, u8* ecc);
void nand_write_cluster(int cluster_number, u8* cluster, u8* hmac);

int nand_read_cluster_decrypted(int cluster_number, u8* cluster, u8* ecc);
void nand_write_cluster_encrypted(int cluster_number, u8* cluster, u8* ecc);

int nand_init(char* nand_file);
void nand_exit();
