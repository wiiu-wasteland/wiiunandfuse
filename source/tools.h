// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef _TOOLS_H
#define _TOOLS_H

#ifdef _WIN32
#define __LITTLE_ENDIAN 1234
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif
#include <endian.h>
#include <stdint.h>

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

u16 read16be(const u8* p);
u32 read32be(const u8* p);
u64 read64be(const u8* p);

void write16be(u8* p, u16 x);
void write32be(u8* p, u32 x);
void write64be(u8* p, u64 x);

u16 be16(u16 x);
u32 be32(u32 x);
u64 be64(u64 x);

#endif
