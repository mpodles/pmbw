/******************************************************************************
 * funcs_arm64.h
 *
 * All Test Functions in 64-bit ARM assembly code: they are codenamed as
 * Scan/Perm Read/Write 32/64 Ptr/Index Simple/Unroll/Multi Loop.
 *
 * Scan = consecutive scanning, Perm = walk permutation cycle.
 * Read/Write = obvious
 * 32/64 = size of access
 * Ptr = with pointer, Index = access as array[i]
 * Simple/Unroll = 1 or 16 operations per loop,
 *     Multi = ARM multi-register operation
 *
 ******************************************************************************
 * Copyright (C) 2013-2016 Timo Bingmann <tb@panthema.net>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************/

// ****************************************************************************
// ----------------------------------------------------------------------------
// 32-bit Operations
// ----------------------------------------------------------------------------
// ****************************************************************************

// 32-bit writer in a simple loop (C version)
void cScanWrite32PtrSimpleLoop(char* memarea, size_t size, size_t repeats)
{
    uint32_t* begin = (uint32_t*)memarea;
    uint32_t* end = begin + size / sizeof(uint32_t);
    uint32_t value = 0xC0FFEEEE;

    do {
        uint32_t* p = begin;
        do {
            *p++ = value;
        }
        while (p < end);
    }
    while (--repeats != 0);
}

// REGISTER(cScanWrite32PtrSimpleLoop, 4, 4, 1);

// 32-bit writer in a simple loop (Assembler version)
void ScanWrite32PtrSimpleLoop(char* memarea, size_t size, size_t repeats)
{
    uint32_t value = 0xC0FFEEEE;

    asm volatile(
        "1: \n" // start of repeat loop
        "mov    x0, %[memarea] \n"      // x0 = reset loop iterator
        "mov    x1, %[value] \n"        // x1 = some value to copy
        "2: \n" // start of write loop
        "str    w1, [x0], #4 \n"        // store and advance 4
        // test write loop condition
        "cmp    x0, %[end] \n"          // compare to end iterator
        "blo    2b \n"
        // test repeat loop condition
        "subs   %[repeats], %[repeats], #1 \n" // until repeats = 0
        "bne    1b \n"
        : [repeats] "+r" (repeats)
        : [value] "r" (value), [memarea] "r" (memarea), [end] "r" (memarea+size)
        : "x0", "x1", "cc", "memory");
}

REGISTER(ScanWrite32PtrSimpleLoop, 4, 4, 1);

// 32-bit writer in an unrolled loop (Assembler version)
void ScanWrite32PtrUnrollLoop(char* memarea, size_t size, size_t repeats)
{
    uint32_t value = 0xC0FFEEEE;

    asm volatile(
        "1: \n" // start of repeat loop
        "mov    x0, %[memarea] \n"      // x0 = reset loop iterator
        "mov    x1, %[value] \n"        // x1 = some value to copy
        "2: \n" // start of write loop
        "str    w1, [x0,#0*4] \n"
        "str    w1, [x0,#1*4] \n"
        "str    w1, [x0,#2*4] \n"
        "str    w1, [x0,#3*4] \n"

        "str    w1, [x0,#4*4] \n"
        "str    w1, [x0,#5*4] \n"
        "str    w1, [x0,#6*4] \n"
        "str    w1, [x0,#7*4] \n"

        "str    w1, [x0,#8*4] \n"
        "str    w1, [x0,#9*4] \n"
        "str    w1, [x0,#10*4] \n"
        "str    w1, [x0,#11*4] \n"

        "str    w1, [x0,#12*4] \n"
        "str    w1, [x0,#13*4] \n"
        "str    w1, [x0,#14*4] \n"
        "str    w1, [x0,#15*4] \n"

        "add    x0, x0, #16*4 \n"       // add offset
        // test write loop condition
        "cmp    x0, %[end] \n"          // compare to end iterator
        "blo    2b \n"
        // test repeat loop condition
        "subs   %[repeats], %[repeats], #1 \n" // until repeats = 0
        "bne    1b \n"
        : [repeats] "+r" (repeats)
        : [value] "r" (value), [memarea] "r" (memarea), [end] "r" (memarea+size)
        : "x0", "x1", "cc", "memory");
}

REGISTER(ScanWrite32PtrUnrollLoop, 4, 4, 16);

// 32-bit read in a simple loop (Assembler version)
void ScanRead32PtrSimpleLoop(char* memarea, size_t size, size_t repeats)
{
    asm volatile(
        "1: \n" // start of repeat loop
        "mov    x0, %[memarea] \n"      // x0 = reset loop iterator
        "2: \n" // start of read loop
        "ldr    w1, [x0], #4 \n"        // retrieve and advance 4
        // test read loop condition
        "cmp    x0, %[end] \n"          // compare to end iterator
        "blo    2b \n"
        // test repeat loop condition
        "subs   %[repeats], %[repeats], #1 \n" // until repeats = 0
        "bne    1b \n"
        : [repeats] "+r" (repeats)
        : [memarea] "r" (memarea), [end] "r" (memarea+size)
        : "x0", "x1", "cc", "memory");
}

REGISTER(ScanRead32PtrSimpleLoop, 4, 4, 1);

// 32-bit reader in an unrolled loop (Assembler version)
void ScanRead32PtrUnrollLoop(char* memarea, size_t size, size_t repeats)
{
    asm volatile(
        "1: \n" // start of repeat loop
        "mov    x0, %[memarea] \n"      // x0 = reset loop iterator
        "2: \n" // start of read loop
        "ldr    w1, [x0,#0*4] \n"
        "ldr    w1, [x0,#1*4] \n"
        "ldr    w1, [x0,#2*4] \n"
        "ldr    w1, [x0,#3*4] \n"

        "ldr    w1, [x0,#4*4] \n"
        "ldr    w1, [x0,#5*4] \n"
        "ldr    w1, [x0,#6*4] \n"
        "ldr    w1, [x0,#7*4] \n"

        "ldr    w1, [x0,#8*4] \n"
        "ldr    w1, [x0,#9*4] \n"
        "ldr    w1, [x0,#10*4] \n"
        "ldr    w1, [x0,#11*4] \n"

        "ldr    w1, [x0,#12*4] \n"
        "ldr    w1, [x0,#13*4] \n"
        "ldr    w1, [x0,#14*4] \n"
        "ldr    w1, [x0,#15*4] \n"

        "add    x0, x0, #16*4 \n"       // add offset
        // test read loop condition
        "cmp    x0, %[end] \n"          // compare to end iterator
        "blo    2b \n"
        // test repeat loop condition
        "subs   %[repeats], %[repeats], #1 \n" // until repeats = 0
        "bne    1b \n"
        : [repeats] "+r" (repeats)
        : [memarea] "r" (memarea), [end] "r" (memarea+size)
        : "x0", "x1", "cc", "memory");
}

REGISTER(ScanRead32PtrUnrollLoop, 4, 4, 16);

// -----------------------------------------------------------------------------

// 32-bit writer in an indexed loop (C version)
void cScanWrite32IndexSimpleLoop(char* _memarea, size_t _size, size_t repeats)
{
    uint32_t* memarea = (uint32_t*)_memarea;
    uint32_t size = _size / sizeof(uint32_t);
    uint32_t value = 0xC0FFEEEE;

    do {
        for (size_t i = 0; i < size; ++i)
            memarea[i] = value;
    }
    while (--repeats != 0);
}

// REGISTER(cScanWrite32IndexSimpleLoop, 4, 4, 1);

// 32-bit writer in an indexed loop (Assembler version)
void ScanWrite32IndexSimpleLoop(char* memarea, size_t size, size_t repeats)
{
    uint32_t value = 0xC0FFEEEE;

    asm volatile(
        "1: \n" // start of repeat loop
        "mov    x0, #0 \n"              // x0 = reset index
        "mov    x1, %[value] \n"        // x1 = some value to copy
        "2: \n" // start of write loop
        "str    w1, [%[memarea], x0] \n" // store and advance 4
        "add    x0, x0, #4 \n"
        // test write loop condition
        "cmp    x0, %[size] \n"         // compare to total size
        "blo    2b \n"
        // test repeat loop condition
        "subs   %[repeats], %[repeats], #1 \n" // until repeats = 0
        "bne    1b \n"
        : [repeats] "+r" (repeats)
        : [value] "r" (value), [memarea] "r" (memarea), [size] "r" (size)
        : "x0", "x1", "cc", "memory");
}

REGISTER(ScanWrite32IndexSimpleLoop, 4, 4, 1);

// 32-bit reader in an indexed loop (Assembler version)
void ScanRead32IndexSimpleLoop(char* memarea, size_t size, size_t repeats)
{
    asm volatile(
        "1: \n" // start of repeat loop
        "mov    x0, #0 \n"              // x0 = reset index
        "2: \n" // start of read loop
        "ldr    w1, [%[memarea], x0] \n" // store and advance 4
        "add    x0, x0, #4 \n"
        // test read loop condition
        "cmp    x0, %[size] \n"         // compare to total size
        "blo    2b \n"
        // test repeat loop condition
        "subs   %[repeats], %[repeats], #1 \n" // until repeats = 0
        "bne    1b \n"
        : [repeats] "+r" (repeats)
        : [memarea] "r" (memarea), [size] "r" (size)
        : "x0", "x1", "cc", "memory");
}

REGISTER(ScanRead32IndexSimpleLoop, 4, 4, 1);

// ****************************************************************************
// ----------------------------------------------------------------------------
// 64-bit Operations
// ----------------------------------------------------------------------------
// ****************************************************************************

// 64-bit writer in a simple loop (C version)
void cScanWrite64PtrSimpleLoop(char* memarea, size_t size, size_t repeats)
{
    typedef std::pair<uint32_t,uint32_t> uint64;

    uint64* begin = (uint64*)memarea;
    uint64* end = begin + size / sizeof(uint64);
    uint32_t val32 = 0xC0FFEEEE;
    uint64 value = uint64(val32,val32);

    do {
        uint64* p = begin;
        do {
            *p++ = value;
        }
        while(p < end);
    }
    while (--repeats != 0);
}

// REGISTER(cScanWrite64PtrSimpleLoop, 8, 8, 1);

// 64-bit writer in a simple loop (Assembler version)
void ScanWrite64PtrSimpleLoop(char* memarea, size_t size, size_t repeats)
{
    uint64_t value = 0xC0FFEEEE;

    asm volatile(
        "mov    x1, %[value] \n"        // x1 = 64-bit value
        "1: \n" // start of repeat loop
        "mov    x0, %[memarea] \n"      // x0 = reset loop iterator
        "2: \n" // start of write loop
        "str    x1, [x0], #8 \n"        // store and advance 8
        // test write loop condition
        "cmp    x0, %[end] \n"          // compare to end iterator
        "blo    2b \n"
        // test repeat loop condition
        "subs   %[repeats], %[repeats], #1 \n" // until repeats = 0
        "bne    1b \n"
        : [repeats] "+r" (repeats)
        : [value] "r" (value), [memarea] "r" (memarea), [end] "r" (memarea+size)
        : "x0", "x1", "cc", "memory");
}

REGISTER(ScanWrite64PtrSimpleLoop, 8, 8, 1);

// 64-bit writer in an unrolled loop (Assembler version)
void ScanWrite64PtrUnrollLoop(char* memarea, size_t size, size_t repeats)
{
    uint64_t value = 0xC0FFEEEE;

    asm volatile(
        "mov    x1, %[value] \n"        // x1 = 64-bit value
        "1: \n" // start of repeat loop
        "mov    x0, %[memarea] \n"      // x0 = reset loop iterator
        "2: \n" // start of write loop
        "str    x1, [x0,#0*8] \n"
        "str    x1, [x0,#1*8] \n"
        "str    x1, [x0,#2*8] \n"
        "str    x1, [x0,#3*8] \n"

        "str    x1, [x0,#4*8] \n"
        "str    x1, [x0,#5*8] \n"
        "str    x1, [x0,#6*8] \n"
        "str    x1, [x0,#7*8] \n"

        "str    x1, [x0,#8*8] \n"
        "str    x1, [x0,#9*8] \n"
        "str    x1, [x0,#10*8] \n"
        "str    x1, [x0,#11*8] \n"

        "str    x1, [x0,#12*8] \n"
        "str    x1, [x0,#13*8] \n"
        "str    x1, [x0,#14*8] \n"
        "str    x1, [x0,#15*8] \n"

        "add    x0, x0, #16*8 \n"
        // test write loop condition
        "cmp    x0, %[end] \n"          // compare to end iterator
        "blo    2b \n"
        // test repeat loop condition
        "subs   %[repeats], %[repeats], #1 \n" // until repeats = 0
        "bne    1b \n"
        : [repeats] "+r" (repeats)
        : [value] "r" (value), [memarea] "r" (memarea), [end] "r" (memarea+size)
        : "x0", "x1", "cc", "memory");
}

REGISTER(ScanWrite64PtrUnrollLoop, 8, 8, 16);

// 64-bit reader in a simple loop (Assembler version)
void ScanRead64PtrSimpleLoop(char* memarea, size_t size, size_t repeats)
{
    asm volatile(
        "1: \n" // start of repeat loop
        "mov    x0, %[memarea] \n"      // x0 = reset loop iterator
        "2: \n" // start of read loop
        "ldr    x1, [x0], #8 \n"        // retrieve and advance 8
        // test read loop condition
        "cmp    x0, %[end] \n"          // compare to end iterator
        "blo    2b \n"
        // test repeat loop condition
        "subs   %[repeats], %[repeats], #1 \n" // until repeats = 0
        "bne    1b \n"
        : [repeats] "+r" (repeats)
        : [memarea] "r" (memarea), [end] "r" (memarea+size)
        : "x0", "x1", "r5", "cc", "memory");
}

REGISTER(ScanRead64PtrSimpleLoop, 8, 8, 1);

void ScanRW64PtrSimpleLoop(char* memarea, size_t size, size_t repeats)
{
    uint64_t value = 0xC0FFEEEE;

    asm volatile(
        "mov    x1, %[value] \n"        // x1 = 64-bit value
        "1: \n" // start of repeat loop
        "mov    x0, %[memarea] \n"      // x0 = reset loop iterator
        "2: \n" // start of read-write loop
        "ldr    x1, [x0], #8 \n"        // value pointed by x0 into x1, move x0 forward 8 bytes
        "str    x1, [x0] \n"        // store x1 value into what is pointed by x0
        // test write loop condition
        "cmp    x0, %[end] \n"          // compare to end iterator
        "blo    2b \n"
        // test repeat loop condition
        "subs   %[repeats], %[repeats], #1 \n" // until repeats = 0
        "bne    1b \n"
        : [repeats] "+r" (repeats)
        : [value] "r" (value), [memarea] "r" (memarea), [end] "r" (memarea+size)
        : "x0", "x1", "cc", "memory");
}

REGISTER(ScanRW64PtrSimpleLoop, 8,8, 1);

// 64-bit reader in an unrolled loop (Assembler version)
void ScanRead64PtrUnrollLoop(char* memarea, size_t size, size_t repeats)
{
    asm volatile(
        "1: \n" // start of repeat loop
        "mov    x0, %[memarea] \n"      // x0 = reset loop iterator
        "2: \n" // start of read loop
        "ldr    x1, [x0,#0*8] \n"
        "ldr    x1, [x0,#1*8] \n"
        "ldr    x1, [x0,#2*8] \n"
        "ldr    x1, [x0,#3*8] \n"

        "ldr    x1, [x0,#4*8] \n"
        "ldr    x1, [x0,#5*8] \n"
        "ldr    x1, [x0,#6*8] \n"
        "ldr    x1, [x0,#7*8] \n"

        "ldr    x1, [x0,#8*8] \n"
        "ldr    x1, [x0,#9*8] \n"
        "ldr    x1, [x0,#10*8] \n"
        "ldr    x1, [x0,#11*8] \n"

        "ldr    x1, [x0,#12*8] \n"
        "ldr    x1, [x0,#13*8] \n"
        "ldr    x1, [x0,#14*8] \n"
        "ldr    x1, [x0,#15*8] \n"

        "add    x0, x0, #16*8 \n"
        // test read loop condition
        "cmp    x0, %[end] \n"          // compare to end iterator
        "blo    2b \n"
        // test repeat loop condition
        "subs   %[repeats], %[repeats], #1 \n" // until repeats = 0
        "bne    1b \n"
        : [repeats] "+r" (repeats)
        : [memarea] "r" (memarea), [end] "r" (memarea+size)
        : "x0", "x1", "r5", "cc", "memory");
}

REGISTER(ScanRead64PtrUnrollLoop, 8, 8, 16);

// ****************************************************************************
// ----------------------------------------------------------------------------
// Permutation Walking
// ----------------------------------------------------------------------------
// ****************************************************************************

// follow 64-bit permutation in a simple loop (C version)
void cPermRead64SimpleLoop(char* memarea, size_t, size_t repeats)
{
    uint64_t* begin = (uint64_t*)memarea;
    uint64_t* p;
    do {
        p = begin;
        do {
            p = (uint64_t*)*p;
        }
        while (p != begin);
    }
    while (--repeats != 0);
    p++;
}

REGISTER_PERM(cPermRead64SimpleLoop, 4, 1);

// follow 64-bit permutation in a simple loop (C version)
void cPermRead64SimpleLoop2Block(char* memarea, size_t, size_t repeats)
{
    uint64_t* begin = (uint64_t*)memarea;

    uint64_t* p;
    uint64_t* adj_1;
    do {
        p = begin;
        adj_1 = begin + 1;
        do {
            p = (uint64_t*)*p;
            adj_1 = (uint64_t*)*adj_1; 
        }
        while (p != begin);
    }
    while (--repeats != 0);
    p++;
    adj_1++;
}

REGISTER_PERM(cPermRead64SimpleLoop2Block, 4, 2);


// follow 64-bit permutation in a simple loop (C version)
void cPermRead64SimpleLoop4Block(char* memarea, size_t, size_t repeats)
{
    uint64_t* begin = (uint64_t*)memarea;

    uint64_t* p;
    uint64_t* adj_1;
    uint64_t* adj_2;
    uint64_t* adj_3;
    do {
        p = begin;
        adj_1 = begin + 1;
        adj_2 = begin + 2;
        adj_3 = begin + 3;
        do {
            p = (uint64_t*)*p;
            adj_1 = (uint64_t*)*adj_1; 
            adj_2 = (uint64_t*)*adj_2; 
            adj_3 = (uint64_t*)*adj_3; 
        }
        while (p != begin);
    }
    while (--repeats != 0);
    p++;
    adj_1++;
    adj_2++;
    adj_3++;
}

REGISTER_PERM(cPermRead64SimpleLoop4Block, 4, 4);

// follow 64-bit permutation in a simple loop (C version)
void cPermRead64SimpleLoop8Block(char* memarea, size_t, size_t repeats)
{
    uint64_t* begin = (uint64_t*)memarea;

    uint64_t* p;
    uint64_t* adj_1;
    uint64_t* adj_2;
    uint64_t* adj_3;
    uint64_t* adj_4;
    uint64_t* adj_5;
    uint64_t* adj_6;
    uint64_t* adj_7;
    do {
        p = begin;
        adj_1 = begin + 1;
        adj_2 = begin + 2;
        adj_3 = begin + 3;
        adj_4 = begin + 4;
        adj_5 = begin + 5;
        adj_6 = begin + 6;
        adj_7 = begin + 7;
        do {
            p = (uint64_t*)*p;
            adj_1 = (uint64_t*)*adj_1; 
            adj_2 = (uint64_t*)*adj_2; 
            adj_3 = (uint64_t*)*adj_3; 
            adj_4 = (uint64_t*)*adj_4; 
            adj_5 = (uint64_t*)*adj_5; 
            adj_6 = (uint64_t*)*adj_6; 
            adj_7 = (uint64_t*)*adj_7; 
        }
        while (p != begin);
    }
    while (--repeats != 0);
    p++;
    adj_1++;
    adj_2++;
    adj_3++;
    adj_4++;
    adj_5++;
    adj_6++;
    adj_7++;
}

REGISTER_PERM(cPermRead64SimpleLoop8Block, 4, 8);

// follow 64-bit permutation in a simple loop (Assembler version)
void PermRead64SimpleLoop(char* memarea, size_t, size_t repeats)
{
    asm volatile(
        "1: \n" // start of repeat loop
        "mov    x0, %[memarea] \n"      // x0 = reset iterator
        "2: \n" // start of loop
        "ldr    x0, [x0] \n"
        // test loop condition
        "cmp    x0, %[memarea] \n"      // compare to end iterator
        "bne    2b \n"
        // test repeat loop condition
        "subs   %[repeats], %[repeats], #1 \n" // until repeats = 0
        "bne    1b \n"
        : [repeats] "+r" (repeats)
        : [memarea] "r" (memarea)
        : "x0", "cc", "memory");
}

REGISTER_PERM(PermRead64SimpleLoop, 4, 1);

// follow 64-bit permutation in an unrolled loop (Assembler version)
void PermRead64UnrollLoop(char* memarea, size_t, size_t repeats)
{
    asm volatile(
        "1: \n" // start of repeat loop
        "mov    x0, %[memarea] \n"      // x0 = reset iterator
        "2: \n" // start of loop
        "ldr    x0, [x0] \n"
        "ldr    x0, [x0] \n"
        "ldr    x0, [x0] \n"
        "ldr    x0, [x0] \n"

        "ldr    x0, [x0] \n"
        "ldr    x0, [x0] \n"
        "ldr    x0, [x0] \n"
        "ldr    x0, [x0] \n"

        "ldr    x0, [x0] \n"
        "ldr    x0, [x0] \n"
        "ldr    x0, [x0] \n"
        "ldr    x0, [x0] \n"

        "ldr    x0, [x0] \n"
        "ldr    x0, [x0] \n"
        "ldr    x0, [x0] \n"
        "ldr    x0, [x0] \n"
        // test loop condition
        "cmp    x0, %[memarea] \n"      // compare to end iterator
        "bne    2b \n"
        // test repeat loop condition
        "subs   %[repeats], %[repeats], #1 \n" // until repeats = 0
        "bne    1b \n"
        : [repeats] "+r" (repeats)
        : [memarea] "r" (memarea)
        : "x0", "cc", "memory");
}

REGISTER_PERM(PermRead64UnrollLoop, 4, 1);

// -----------------------------------------------------------------------------
