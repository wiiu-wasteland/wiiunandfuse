// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include "tools.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define __LITTLE_ENDIAN 1234
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif
#include <endian.h>

//
// basic data types
//

u16 read16be(const u8* p)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return (p[0] << 8) | p[1];
#else
    return (u16)*p;
#endif
}

u32 read32be(const u8* p)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
#else
    return (u32)*p;
#endif
}

u64 read64be(const u8* p)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return ((u64)read32be(p) << 32) | read32be(p + 4);
#else
    return (u64)*p;
#endif
}

void write16be(u8* p, u16 x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    p[0] = x >> 8;
    p[1] = x;
#else
    (u16)* p = x;
#endif
}

void write32be(u8* p, u32 x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    write16be(p, x >> 16);
    write16be(p + 2, x);
#else
    (u32)* p = x;
#endif
}

void write64be(u8* p, u64 x)
{
    write32be(p, x >> 32);
    write32be(p + 4, x);
}

u16 be16(u16 x)
{
    return read16be((u8*)&x);
}

u32 be32(u32 x)
{
    return read32be((u8*)&x);
}

u64 be64(u64 x)
{
    return read64be((u8*)&x);
}
