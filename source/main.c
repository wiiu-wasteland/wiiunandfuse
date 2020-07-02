/*
wiinandfuse is licensed under the MIT license:
Copyright (c) 2010 yellowstar6

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the Software), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies
or substantial portions of the Software.

THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

#include <errno.h>
#include <fuse.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <syslog.h>
#include <unistd.h>

#include "crypto.h"
#include "ecc.h"
#include "nand.h"
#include "crypto.h"
#include "tools.h"

#define ISFS_NAME_LEN 12


#define CLUSTER_ENDCHAIN    0xFFFB  /* last cluster within a chain */
#define CLUSTER_RESERVED    0xFFFC  /* reserved cluster */
#define CLUSTER_BADBLOCK    0xFFFD  /* bad nand block */
#define CLUSTER_FREE        0xFFFE  /* empty space */
#define CLUSTER_UNALLOCATED 0xFFFF  /* cluster not yet allocated for file */

typedef struct {
    char name[ISFS_NAME_LEN];
    unsigned char mode;
    unsigned char attr;
    union {
        unsigned short first_child;
        unsigned short first_cluster;
    };
    unsigned short sibling;
    unsigned int size;
    unsigned int uid;
    unsigned short gid;
    unsigned int dummy;
} __attribute__((packed)) isfs_file_node;

typedef struct {
    unsigned char magic[4];
    unsigned int version;
    unsigned int dummy;

    unsigned short cluster_table[32768];
    isfs_file_node files[6143];
    unsigned char padding[0x14]; //Added by yellowstar6.
} __attribute__((packed)) isfs_superblock;

typedef struct {
    unsigned short first_cluster;
    unsigned short cur_cluster;
    unsigned int size;
    unsigned int offset;
    unsigned int cluster_index;
    unsigned int nodeindex;
    isfs_file_node* node;
} isfs_fp;

isfs_superblock ISFS;
unsigned int used_fds = 0;
isfs_fp fd_array[32];

int ISFS_only = 0;
int use_nand_permissions = 0;
int hmac_abort = 0;
int ignore_ecc = 0;

int supercluster = -1;
unsigned int isfs_cluster = 0;
unsigned int isfs_version = 0;

static unsigned char buffer[8 * 2048];

unsigned short nand_nodeindex = 0;

int isfs_init()
{
    int i;
    int si = -1;
    unsigned char buf[0x800];
    isfs_superblock* bufptr = (isfs_superblock*)buf;
    unsigned char* isfsptr = (unsigned char*)&ISFS;
    unsigned char supercluster_hmac[0x80];
    unsigned char calc_hmac[20];

    for (i = 0x7f00; i < 0x7fff; i += 0x10) {
        si++;
        nand_read_sector(i * 8, 1, buf, NULL);

        if (memcmp(bufptr->magic, "SFFS", 4) && memcmp(bufptr->magic, "SFS!", 4))
            continue;

        if (isfs_cluster == 0 || isfs_version < be32(bufptr->version)) {
            isfs_cluster = i;
            isfs_version = be32(bufptr->version);
            supercluster = si;
        }
    }

    if (isfs_cluster == 0) {
        printf("No ISFS supercluster found. Your NAND ISFS is seriously broken.\n");
        return -1;
    }

    // read superblock
    memset(&ISFS, 0, 0x40000);
    for (i = 0; i < 16; i++) {
        nand_read_cluster(isfs_cluster + i, isfsptr, supercluster_hmac);
        isfsptr += 0x4000;
    }

    // load nand aes key/hmac
    if (!memcmp(ISFS.magic, "SFFS", 4))
        crypto_init(0); // vwii/slccmpt (SFFS)
    else
        crypto_init(1); // wiiu/slc (SFS!)

    // compute hmac
    memset(calc_hmac, 0, 20);
    crypto_nand_hmac_meta(&ISFS, isfs_cluster, calc_hmac);

    if (memcmp(&supercluster_hmac[1], calc_hmac, 20)) {
        printf("ISFS HMAC calc failed.\n");
        if (hmac_abort)
            return -1;
    }

    // hmac valid
    printf("ISFS HMAC valid.\n");

    return 0;
}

int isfs_update()
{
    unsigned char calc_hmac[20];
    int i;
    unsigned char* isfsptr = (unsigned char*)&ISFS;
    memset(calc_hmac, 0, 20);

    supercluster++;

    if (supercluster > 15)
        supercluster = 0;
    isfs_cluster = 0x7f00 + (supercluster * 0x10);

    crypto_nand_hmac_meta(&ISFS, isfs_cluster, calc_hmac);
    for (i = 0; i < 16; i++) {
        nand_write_cluster(isfs_cluster + i, isfsptr, i == 15 ? calc_hmac : NULL);
        isfsptr += 0x4000;
    }

    return 0;
}

int isfs_findemptynode()
{
    int i;
    for (i = 0; i < 6143; i++) {
        if (ISFS.files[i].mode == 0)
            break;
    }
    if (i == 6142)
        return -ENOSPC;
    return i;
}

int isfs_allocatecluster()
{
    int i;
    unsigned short clus;
    for (i = 0; i < 0x8000; i++) {
        clus = be16(ISFS.cluster_table[i]);
        if (clus == CLUSTER_FREE)
            break;
    }
    if (i == 0x7fff)
        return -ENOSPC;
    ISFS.cluster_table[i] = be16(CLUSTER_ENDCHAIN);
    return i;
}

int isfs_open(isfs_file_node* fp, const char* path, int type, unsigned short* index) //This is based on the function from MINI ppcskel isfs.c
{
    char *ptr, *ptr2;
    unsigned int len;
    isfs_file_node* cur = ISFS.files;
    nand_nodeindex = 0;

    memset(fp, 0, sizeof(isfs_file_node));

    if (strcmp(cur->name, "/") != 0) {
        syslog(LOG_DEBUG, "your isfs is corrupted. fixit!\n");
        return -1;
    }

    if (strcmp(path, "/") != 0) {
        nand_nodeindex = be16(cur->first_child);
        cur = &ISFS.files[be16(cur->first_child)];
    }

    if (strcmp(path, "/") != 0) {
        ptr = (char*)path;
        do {
            ptr++;
            ptr2 = strchr(ptr, '/');
            if (ptr2 == NULL)
                len = strlen(ptr);
            else {
                ptr2++;
                len = ptr2 - ptr - 1;
            }
            if (len > 12) {
                printf("invalid length: %s %s %s [%d]\n",
                    ptr, ptr2, path, len);
                return -1;
            }

            for (;;) {
                if (ptr2 != NULL && strncmp(cur->name, ptr, len) == 0
                    && strnlen(cur->name, 12) == len
                    && (cur->mode & 3) == 2
                    && (signed short)(be16(cur->first_child) & 0xffff) != (signed short)0xffff) {
                    nand_nodeindex = be16(cur->first_child);
                    cur = &ISFS.files[be16(cur->first_child)];
                    ptr = ptr2 - 1;
                    break;
                } else if (ptr2 == NULL && strncmp(cur->name, ptr, len) == 0 && strnlen(cur->name, 12) == len && (cur->mode & 3) == type) {
                    break;
                } else if ((cur->sibling & 0xffff) != 0xffff) {
                    nand_nodeindex = be16(cur->sibling);
                    cur = &ISFS.files[be16(cur->sibling)];
                } else {
                    return -1;
                }
            }

        } while (ptr2 != NULL);
    }

    memcpy(fp, cur, sizeof(isfs_file_node));
    return 0;
}

int isfs_read(void* ptr, unsigned int size, unsigned int nmemb, isfs_fp* fp) //Based on Bootmii MINI ppcskel isfs.c
{
    unsigned int total = size * nmemb;
    unsigned int copy_offset, copy_len;
    int retval;
    int realtotal = (unsigned int)total;
    unsigned char calc_hmac[20];
    unsigned char spare[0x80];

    if (fp->offset + total > fp->size)
        total = fp->size - fp->offset;

    if (total == 0)
        return 0;

    if (fp->cur_cluster == 0xffff) {
        syslog(LOG_DEBUG, "Erm, clus = 0xffff");
        return -EIO;
    }

    realtotal = (unsigned int)total;
    while (total > 0) {
        syslog(LOG_DEBUG, "clus %x", fp->cur_cluster);
        retval = nand_read_cluster_decrypted(fp->cur_cluster, buffer, spare);
        if (retval < 0 && !ignore_ecc)
            return -EIO;
        crypto_nand_hmac_data(buffer, be32(fp->node->uid), fp->node->name, fp->nodeindex, be32(fp->node->dummy), fp->cluster_index, calc_hmac);
        if (hmac_abort && memcmp(calc_hmac, &spare[1], 20) != 0) {
            syslog(LOG_DEBUG, "Bad cluster HMAC.");
            return -EIO;
        }
        copy_offset = fp->offset % (2048 * 8);
        copy_len = (2048 * 8) - copy_offset;
        if (copy_len > total)
            copy_len = total;
        memcpy(ptr, buffer + copy_offset, copy_len);
        ptr += copy_len;
        total -= copy_len;
        fp->offset += copy_len;

        if ((copy_offset + copy_len) >= (2048 * 8)) {
            fp->cur_cluster = be16(ISFS.cluster_table[fp->cur_cluster]);
            fp->cluster_index++;
        }
    }

    return realtotal;
}

int isfs_write(void* ptr, unsigned int size, unsigned int nmemb, isfs_fp* fp) //Based on Bootmii MINI ppcskel isfs.c
{
    unsigned int total = size * nmemb;
    unsigned int copy_offset, copy_len;
    int retval;
    int realtotal = (unsigned int)total;
    unsigned char calc_hmac[20];
    unsigned char spare[0x80];

    if (total == 0)
        return 0;

    if (fp->cur_cluster == fp->first_cluster && fp->cur_cluster == 0xffff) {
        fp->first_cluster = isfs_allocatecluster();
        fp->cur_cluster = fp->first_cluster;
        fp->node->first_cluster = be16(fp->first_cluster);
    }

    realtotal = (unsigned int)total;
    while (total > 0) {
        retval = nand_read_cluster_decrypted(fp->cur_cluster, buffer, spare);
        if (retval < 0 && !ignore_ecc)
            return -EIO;

        copy_offset = fp->offset % (2048 * 8);
        copy_len = (2048 * 8) - copy_offset;
        if (copy_len > total)
            copy_len = total;
        memcpy(buffer + copy_offset, ptr, copy_len);
        ptr += copy_len;
        total -= copy_len;
        fp->offset += copy_len;

        crypto_nand_hmac_data(buffer, be32(fp->node->uid), fp->node->name, fp->nodeindex, be32(fp->node->dummy), fp->cluster_index, calc_hmac);

        nand_write_cluster_encrypted(fp->cur_cluster, buffer, calc_hmac);

        if ((copy_offset + copy_len) >= (2048 * 8)) {
            if (be16(ISFS.cluster_table[fp->cur_cluster]) == CLUSTER_ENDCHAIN)
                ISFS.cluster_table[fp->cur_cluster] = be16(isfs_allocatecluster());
            fp->cur_cluster = be16(ISFS.cluster_table[fp->cur_cluster]);
            fp->cluster_index++;
        }
    }

    if (fp->offset > fp->size) {
        fp->size = fp->offset;
        fp->node->size = be32(fp->size);
    }
    isfs_update();
    return realtotal;
}

int isfs_seek(isfs_fp* fp, unsigned int where, unsigned int whence)
{
    int clusters = 0;
    if (whence == SEEK_SET)
        fp->offset = where;
    if (whence == SEEK_CUR)
        fp->offset += where;
    if (whence == SEEK_END)
        fp->offset = fp->size;
    if (fp->offset > fp->size)
        return -EINVAL;

    if (fp->offset)
        clusters = fp->offset / 0x4000;
    syslog(LOG_DEBUG, "seek: clusters %x where %x offset %x", clusters, where, fp->offset);
    fp->cur_cluster = fp->first_cluster;
    fp->cluster_index = 0;
    while (clusters > 0) {
        fp->cur_cluster = be16(ISFS.cluster_table[fp->cur_cluster]);
        clusters--;
        fp->cluster_index++;
    }

    return 0;
}

int isfs_unlink(const char* path, int type, int clear)
{
    int i, stop = 0;
    isfs_file_node cur, dir;
    char parentpath[256];
    unsigned short index, ind, tempcluster, tempclus;

    syslog(LOG_DEBUG, "Unlink: path %s type %d", path, type);
    if (isfs_open(&cur, path, type, &nand_nodeindex) == -1) {
        syslog(LOG_DEBUG, "no ent: %s", path);
        return -ENOENT;
    }
    index = nand_nodeindex;

    for (i = strlen(path) - 1; i > 0 && path[i] != '/'; i--)
        ;
    memset(parentpath, 0, 256);
    strncpy(parentpath, path, i);

    if (isfs_open(&dir, parentpath, 2, &nand_nodeindex) == -1) {
        syslog(LOG_DEBUG, "no ent: %s", parentpath);
        return -ENOENT;
    }
    syslog(LOG_DEBUG, "parent dir %s", parentpath);

    if (dir.first_child != 0xffff) {
        stop = 0;
        ind = be16(dir.first_child);
        memcpy(&dir, &ISFS.files[(int)ind], sizeof(isfs_file_node));
        if (ind != index) {
            do {
                if (be16(dir.sibling) == index)
                    break;
                if (dir.sibling != 0xffff) {
                    ind = be16(dir.sibling);
                    memcpy(&dir, &ISFS.files[ind], sizeof(isfs_file_node));
                } else {
                    stop = 1;
                }
            } while (!stop);
            ISFS.files[ind].sibling = cur.sibling;
        } else {
            ISFS.files[nand_nodeindex].first_child = cur.sibling;
        }
    } else if (type == 2)
        return -ENOTEMPTY;

    syslog(LOG_DEBUG, "found it");
    if (type == 1 && clear == 0) {
        tempcluster = be16(cur.first_cluster);
        while (tempcluster != CLUSTER_ENDCHAIN && tempcluster != 0xffff) {
            tempclus = be16(ISFS.cluster_table[tempcluster]);
            ISFS.cluster_table[tempcluster] = be16(CLUSTER_FREE);
            tempcluster = tempclus;
        }
    }

    syslog(LOG_DEBUG, "stuff");
    if (clear == 0)
        memset(&ISFS.files[index], 0, sizeof(isfs_file_node));
    if (clear > 0)
        ISFS.files[index].sibling = 0xffff;

    isfs_update();
    if (clear > 0)
        return index;
    return 0;
}

int isfs_create(const char* path, int type, mode_t newperms, uid_t uid, gid_t gid, int newnode)
{
    int i, stop = 0;
    int newind = 0;
    isfs_file_node cur, dir;
    char parentpath[256];
    unsigned short ind;

    syslog(LOG_DEBUG, "Create: path %s type %d", path, type);

    for (i = strlen(path) - 1; i > 0 && path[i] != '/'; i--)
        ;
    memset(parentpath, 0, 256);
    strncpy(parentpath, path, i);

    if (isfs_open(&cur, path, type, &nand_nodeindex) >= 0) {
        syslog(LOG_DEBUG, "exists: %s", path);
        return -EEXIST;
    }

    if (isfs_open(&dir, parentpath, 2, &nand_nodeindex) == -1) {
        syslog(LOG_DEBUG, "no ent: %s", parentpath);
        return -ENOENT;
    }
    syslog(LOG_DEBUG, "parent dir %s", parentpath);

    if (newnode == -1)
        newind = isfs_findemptynode();
    if (newnode >= 0)
        newind = newnode;

    if (newnode == -1) {
        memset(&ISFS.files[newind], 0, sizeof(isfs_file_node)); //It should already be all-zero, but make sure it's all zero.
        memset(parentpath, 0, 256);
        strncpy(parentpath, &path[i + 1], 255);
        memcpy(ISFS.files[newind].name, parentpath, 12);

        ISFS.files[newind].mode = type;
        if (newperms & S_IRUSR)
            ISFS.files[newind].mode |= 1 << 6;
        if (newperms & S_IWUSR)
            ISFS.files[newind].mode |= 2 << 6;
        if (newperms & S_IRGRP)
            ISFS.files[newind].mode |= 1 << 4;
        if (newperms & S_IWGRP)
            ISFS.files[newind].mode |= 2 << 4;
        if (newperms & S_IROTH)
            ISFS.files[newind].mode |= 1 << 2;
        if (newperms & S_IWOTH)
            ISFS.files[newind].mode |= 2 << 2;

        ISFS.files[newind].first_cluster = 0xffff;
        ISFS.files[newind].sibling = 0xffff;
        ISFS.files[newind].uid = be32(uid);
        ISFS.files[newind].gid = be16(gid);
    }

    if (dir.first_child != 0xffff) {
        stop = 0;
        ind = be16(dir.first_child);
        memcpy(&dir, &ISFS.files[(int)ind], sizeof(isfs_file_node));
        do {
            if (dir.sibling != 0xffff) {
                ind = be16(dir.sibling);
                memcpy(&dir, &ISFS.files[ind], sizeof(isfs_file_node));
            } else {
                stop = 1;
            }
        } while (!stop);
        ISFS.files[ind].sibling = be16(newind);
    } else {
        ISFS.files[nand_nodeindex].first_child = be16(newind);
    }

    isfs_update();

    return 0;
}

void fs_destroy(void* usr)
{
    nand_exit();
    otp_exit();
    closelog();
}

int fs_statfs(const char* path, struct statvfs* fsinfo)
{
    int freeblocks = 0;
    int i;
    memset(fsinfo, 0, sizeof(struct statvfs));
    fsinfo->f_bsize = 2048;
    fsinfo->f_frsize = 2048 * 8;
    fsinfo->f_blocks = 0x8000 * 8;
    fsinfo->f_namemax = 12;
    for (i = 0; i < 32768; i++) {
        if (be16(ISFS.cluster_table[i]) == 0xFFFE)
            freeblocks++;
    }
    freeblocks *= 8;
    fsinfo->f_bfree = 0;
    fsinfo->f_bavail = freeblocks;
    freeblocks = 6143;
    for (i = 0; i < 6143; i++) {
        if (ISFS.files[i].mode != 0)
            freeblocks--;
    }
    fsinfo->f_ffree = freeblocks;
    fsinfo->f_files = 6143 - freeblocks;
    return 0;
}

static int
fs_getattr(const char* path, struct stat* stbuf)
{
    isfs_file_node cur;
    int type = -1;
    unsigned int perms = 0;
    int i;
    unsigned int perm = 0400;
    syslog(LOG_DEBUG, "getattr %s", path);
    memset(stbuf, 0, sizeof(struct stat));
    if (isfs_open(&cur, path, 1, &nand_nodeindex) > -1) {
        type = 1;
    }

    if (type == -1) {
        if (isfs_open(&cur, path, 2, &nand_nodeindex) > -1) {
            type = 0;
        }
    }

    if (strcmp(path, "/") == 0)
        type = 0;

    if (type == -1) {
        syslog(LOG_DEBUG, "no ent");
        return -ENOENT;
    }

    stbuf->st_atime = -1;
    stbuf->st_mtime = -1;
    stbuf->st_ctime = -1;
    if (use_nand_permissions) {
        stbuf->st_uid = (uid_t)be32(cur.uid);
        stbuf->st_gid = (gid_t)be16(cur.gid);
        syslog(LOG_DEBUG, "perms: %x %x", cur.mode, cur.attr);
        for (i = 0; i < 3; i++) {
            if ((cur.mode >> (6 - (i * 2))) & 1) {
                perms |= perm;
                syslog(LOG_DEBUG, "perm %03x has r new perms %o %o", i, perms, perm);
            }
            if ((cur.mode >> (6 - (i * 2))) & 2) {
                perms |= perm / 02;
                syslog(LOG_DEBUG, "perm %03x has w new perms %o %o", i, perms, perm / 02);
            }
            perm /= 010;
        }
    }

    if (type == 0) {
        if (!use_nand_permissions)
            perms = 0755;
        if (use_nand_permissions)
            perms |= 0111;
        stbuf->st_mode = S_IFDIR | perms;
        stbuf->st_nlink = 2;
        stbuf->st_blksize = 2048;
        syslog(LOG_DEBUG, "Type directory perms %o", perms);
    } else {
        if (!use_nand_permissions)
            perms = 0444;
        stbuf->st_mode = S_IFREG | perms;
        stbuf->st_nlink = 1;
        stbuf->st_size = be32(cur.size);
        stbuf->st_blksize = 2048;
        stbuf->st_blocks = stbuf->st_size / 512;
        stbuf->st_ino = nand_nodeindex;
        syslog(LOG_DEBUG, "Type file %s %02x %o", cur.name, cur.mode, perms);
    }
    return 0;
}

static int
fs_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
    off_t offset, struct fuse_file_info* fi)
{
    isfs_file_node cur;
    char fn[13];
    char str[256];
    int stop;
    memset(fn, 0, 13);
    memset(str, 0, 256);
    //syslog(LOG_DEBUG, "readdir: %s", path);
    if (isfs_open(&cur, path, 2, &nand_nodeindex) == -1) {
        syslog(LOG_DEBUG, "no ent: %s", path);
        return -ENOENT;
    }
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    if (cur.first_child != 0xffff) {
        stop = 0;
        memcpy(&cur, &ISFS.files[be16(cur.first_child)], sizeof(isfs_file_node));
        do {
            memset(fn, 0, 13);
            strncpy(fn, cur.name, 12);
            filler(buf, fn, NULL, 0);
            if (cur.sibling != 0xffff) {
                memcpy(&cur, &ISFS.files[be16(cur.sibling)], sizeof(isfs_file_node));
            } else {
                stop = 1;
            }
        } while (!stop);
    }

    return 0;
}

int fs_rename(const char* path, const char* newpath)
{
    int i, i2, ind;
    isfs_file_node cur;

    syslog(LOG_DEBUG, "Rename: path %s newpath %s", path, newpath);
    if (isfs_open(&cur, path, 1, &nand_nodeindex) == -1) {
        syslog(LOG_DEBUG, "no ent: %s", path);
        return -ENOENT;
    }

    for (i = strlen(newpath) - 1; i > 0 && newpath[i] != '/'; i--)
        ;
    i++;
    for (i2 = strlen(path) - 1; i > 0 && path[i2] != '/'; i2--)
        ;
    i2++;

    strncpy(ISFS.files[nand_nodeindex].name, &newpath[i], 12);
    if (i == i2 && strncmp(path, newpath, i) == 0) {
        isfs_update();
    } else {
        ind = isfs_unlink(path, 1, 1);
        syslog(LOG_DEBUG, "Unlink retval %d", ind);
        if (ind < 0)
            return ind;
        syslog(LOG_DEBUG, "renaming");
        if ((i = isfs_create(newpath, 1, 0, 0, 0, ind)) < 0)
            return i; //isfs_create calls isfs_update, so we don't need to call it again here.
    }

    return 0;
}

int fs_chown(const char* path, uid_t uid, gid_t gid)
{
    isfs_file_node cur;

    if (!use_nand_permissions)
        return 0;
    syslog(LOG_DEBUG, "Chown: path %s uid %x gid %x", path, uid, gid);
    if (isfs_open(&cur, path, 1, &nand_nodeindex) == -1) {
        if (isfs_open(&cur, path, 2, &nand_nodeindex) == -1) {
            syslog(LOG_DEBUG, "no ent: %s", path);
            return -ENOENT;
        }
    }

    ISFS.files[nand_nodeindex].uid = be32((unsigned int)uid);
    ISFS.files[nand_nodeindex].gid = be16((unsigned short)gid);

    isfs_update();

    return 0;
}

int fs_chmod(const char* path, mode_t newperms)
{
    isfs_file_node cur;

    if (!use_nand_permissions)
        return 0;
    syslog(LOG_DEBUG, "Chmod: path %s newperms %o", path, newperms);
    if (isfs_open(&cur, path, 1, &nand_nodeindex) == -1) {
        if (isfs_open(&cur, path, 2, &nand_nodeindex) == -1) {
            syslog(LOG_DEBUG, "no ent: %s", path);
            return -ENOENT;
        }
    }

    ISFS.files[nand_nodeindex].mode &= 3;
    if (newperms & S_IRUSR)
        ISFS.files[nand_nodeindex].mode |= 1 << 6;
    if (newperms & S_IWUSR)
        ISFS.files[nand_nodeindex].mode |= 2 << 6;
    if (newperms & S_IRGRP)
        ISFS.files[nand_nodeindex].mode |= 1 << 4;
    if (newperms & S_IWGRP)
        ISFS.files[nand_nodeindex].mode |= 2 << 4;
    if (newperms & S_IROTH)
        ISFS.files[nand_nodeindex].mode |= 1 << 2;
    if (newperms & S_IWOTH)
        ISFS.files[nand_nodeindex].mode |= 2 << 2;

    isfs_update();

    return 0;
}

int fs_unlink(const char* path)
{
    return isfs_unlink(path, 1, 0);
}

int fs_rmdir(const char* path)
{
    return isfs_unlink(path, 2, 0);
}

int fs_mknod(const char* path, mode_t mode, dev_t dev)
{
    if (!(mode & S_IFREG))
        return -EINVAL;
    return isfs_create(path, 1, mode, 0, 0, -1);
}

int fs_mkdir(const char* path, mode_t mode)
{
    return isfs_create(path, 2, mode, 0, 0, -1);
}

int fs_truncate(const char* path, off_t size)
{
    int oldclusters, newclusters;
    int curcluster, nextcluster;
    isfs_file_node cur;

    syslog(LOG_DEBUG, "truncate: path %s size %ld", path, size);
    if (isfs_open(&cur, path, 1, &nand_nodeindex) == -1) {
        syslog(LOG_DEBUG, "no ent: %s", path);
        return -ENOENT;
    }
    
    /* update size in file metadata */
    ISFS.files[nand_nodeindex].size = be32(size);
    
    /* check if cluster count has changed */
    oldclusters = (be32(cur.size) / 0x4000) + !!(be32(cur.size) % 0x4000);
    newclusters = (size / 0x4000) + !!(size % 0x4000);
    if ((size && (oldclusters == newclusters)) || (be16(cur.first_cluster) == CLUSTER_UNALLOCATED)) {
        /* cluster count hasn't changed */
        isfs_update();
        return 0;
    }

    /* allocate missing clusters */
    curcluster = be16(cur.first_cluster);
    for (int i = 1; i < newclusters; i++) {
        nextcluster = be16(ISFS.cluster_table[curcluster]);
        if (nextcluster == CLUSTER_ENDCHAIN) {
            nextcluster = isfs_allocatecluster();
            ISFS.cluster_table[curcluster] = be16(nextcluster);
            ISFS.cluster_table[nextcluster] = be16(CLUSTER_ENDCHAIN);
        }
        curcluster = nextcluster;
    }
    
    /* free up unneeded clusters */
    for (curcluster = ISFS.cluster_table[curcluster]; curcluster != CLUSTER_ENDCHAIN;) {
        nextcluster = be16(ISFS.cluster_table[curcluster]);
        ISFS.cluster_table[curcluster] = be16(CLUSTER_FREE);
        curcluster = nextcluster;
    }
    if (newclusters == 0) {
        ISFS.cluster_table[be16(cur.first_cluster)] = be16(CLUSTER_FREE);
        cur.first_cluster = be16(CLUSTER_UNALLOCATED);
    }
    
    isfs_update();
    return 0;
}

static int
fs_open(const char* path, struct fuse_file_info* fi)
{
    int i;
    isfs_file_node cur;
    syslog(LOG_DEBUG, "open: %s", path);
    //if((fi->flags & 3) != O_RDONLY)return -EACCES;
    if (used_fds == ~0)
        return -ENFILE;

    syslog(LOG_DEBUG, "Getting node struct...");
    if (isfs_open(&cur, path, 1, &nand_nodeindex) == -1) {
        syslog(LOG_DEBUG, "No ent...");
        if (isfs_open(&cur, path, 2, NULL) > -1) {
            syslog(LOG_DEBUG, "open: not directory %s", path);
            return -ENOTDIR;
        }
        syslog(LOG_DEBUG, "no ent: %s", path);
        return -ENOENT;
    }

    for (i = 0; i < 32; i++) {
        if (!(used_fds & 1 << i))
            break;
    }
    used_fds |= 1 << i;

    syslog(LOG_DEBUG, "Using fd %d nodeindex %x", i, (unsigned int)nand_nodeindex);
    memset(&fd_array[i], 0, sizeof(isfs_fp));
    fd_array[i].node = &ISFS.files[nand_nodeindex];
    fd_array[i].first_cluster = be16(fd_array[i].node->first_cluster);
    fd_array[i].cur_cluster = fd_array[i].first_cluster;
    fd_array[i].size = be32(fd_array[i].node->size);
    fd_array[i].offset = 0;
    fd_array[i].cluster_index = 0;
    fd_array[i].nodeindex = nand_nodeindex;

    fi->fh = (uint64_t)i;
    return 0;
}

static int
fs_release(const char* path, struct fuse_file_info* fi)
{
    syslog(LOG_DEBUG, "closing fd %d", (int)fi->fh);
    if (!(used_fds & 1 << fi->fh))
        return -EBADF;
    used_fds &= ~1 << (unsigned int)fi->fh;
    memset(&fd_array[(int)fi->fh], 0, sizeof(isfs_fp));
    syslog(LOG_DEBUG, "done");
    return 0;
}

static int
fs_read(const char* path, char* buf, size_t size, off_t offset,
    struct fuse_file_info* fi)
{
    syslog(LOG_DEBUG, "read fd %d offset %x size %x", (int)fi->fh, (int)offset, (int)size);
    if (!(used_fds & 1 << fi->fh))
        return -EBADF;
    syslog(LOG_DEBUG, "fd valid");
    memset(buf, 0, size);
    isfs_seek(&fd_array[(int)fi->fh], offset, SEEK_SET);
    int num = isfs_read(buf, size, 1, &fd_array[(int)fi->fh]);
    syslog(LOG_DEBUG, "readbytes %x", num);
    return num;
}

static int
fs_write(const char* path, const char* buf, size_t size, off_t offset,
    struct fuse_file_info* fi)
{
    syslog(LOG_DEBUG, "write fd %d offset %x size %x", (int)fi->fh, (int)offset, (int)size);

    if (!(used_fds & 1 << fi->fh))
        return -EBADF;
    syslog(LOG_DEBUG, "fd valid");
    isfs_seek(&fd_array[(int)fi->fh], offset, SEEK_SET);
    int num = isfs_write((void*)buf, size, 1, &fd_array[(int)fi->fh]);
    syslog(LOG_DEBUG, "writebytes %x", num);
    return num;
}

static const struct fuse_operations fsops = {
    .destroy = fs_destroy,
    .statfs = fs_statfs,
    .getattr = fs_getattr,
    .readdir = fs_readdir,
    .rename = fs_rename,
    .chown = fs_chown,
    .chmod = fs_chmod,
    .unlink = fs_unlink,
    .rmdir = fs_rmdir,
    .mknod = fs_mknod,
    .mkdir = fs_mkdir,
    .truncate = fs_truncate,
    .open = fs_open,
    .release = fs_release,
    .read = fs_read,
    .write = fs_write,
};

static const char *helpstr =
"Mount vWii/WiiU NAND images with FUSE.\n"
"Usage:\n"
"wiiunandfuse <nand.bin> <otp.bin> <mount point> <options>\n"
"Options:\n"
"-p: Use NAND permissions. UID and GUI of objects will be set to the NAND UID/GID, as well as the permissions. This option only enables setting the UID/GID and permissions in stat, the open and readdir functions don't check permissions.\n"
"-v: Abort/EIO if HMAC verification of ISFS or file data fails. If ISFS verification fails, wiinandfuse aborts and NAND isn't mounted. If file data verification fails, read will return EIO.\n"
"-e: Ignore ECC errors, default is disabled. When disabled, when pages have invalid ECC reads return EIO.";

int main(int argc, char** argv)
{
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    int argi;

    puts("wiiunandfuse v1.0");
    puts("Based on wiinandfuse by yellowstar6");
    if (argc < 4) {
        puts(helpstr);
        return 0;
    }

    /* parse command line arguments */
    for (argi = 4; argi < argc; argi++) {
        if (strcmp(argv[argi], "-p") == 0)
            use_nand_permissions = 1;
        if (strcmp(argv[argi], "-v") == 0)
            hmac_abort = 1;
    }

    /* initialize otp */
    if (otp_init(argv[2]) < 0) {
        return -1;
    }

    /* initialize nand */
    if (nand_init(argv[1]) < 0) {
        otp_exit();
        return -1;
    }

    /* start logging */
    openlog("wiiunandfuse", 0, LOG_USER);
    syslog(LOG_DEBUG, "STARTED");

    /* initialize isfs */
    if (isfs_init() < 0) {
        nand_exit();
        otp_exit();
        closelog();
        return 0;
    }

    /* start fuse */
    fuse_opt_add_arg(&args, argv[0]);
    fuse_opt_add_arg(&args, argv[3]);
    //fuse_opt_add_arg(&args, "-o");
    //fuse_opt_add_arg(&args, "allow_root"); //Allow root to access the FS.

    return fuse_main(args.argc, args.argv, &fsops, NULL);
}
