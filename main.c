#include <stdio.h>
#include <string.h>
#include "stdlib.h"
/*
 * Key Maker
 * Yes, that key maker.
 *
 *
 * Will be utilized like so : ./keymaker --caesar/bits (caesar will use an OTP caesar cipher, bits will operate on raw bits) --encrypt/decrypt  secret (text to be encrypted or decrypted) pad (secret one time pad)
 *
 * Pad needs to be generated in a CRYPTOGRAPHICALLY SECURE MANNER!!!!!!!!!!!!!!!!!
 * Needs to be shared via SECURE AND COVERT MEANS! Think ultrasonic RF bursts, steganography, physical meeting with no words spoken only folded papers exchanged, etc.
 *
 * Ideally, the machine doing the encrypting and decrypting should be a dedicated device running linux or bsd WITHOUT an intel or amd chip inside (your best bet would be something like an old 32 bit mips, powerpc, something along these lines) with no wireless or bluetooth
 * capabilities onboard whatsoever. It should have no ethernet connection either, it should be entirely offline, and you should use a usb stick to copy the encrypted message to an insecure device which you can use to send the message over the internet.
 * BSD may be more ideal than linux, I will leave this decision up to you.
 *
 * After using a pad to decrypt a message, you should physically destroy the pad
 *
 * How far you want to go to secure your privacy rights is up to you, but keep the aforementioned things in the forefront of your mind.
 *
*/
void handle_arg(char *arg, int arg_no);
void chip_security_checks();
void os_security_checks();


#define MODE 1 // the encrypt / decrypt mode IE caesar or raw bits
#define CAESAR 0
#define BITS 1

#define OPERATION 2
#define ENCRYPT 0
#define DECRYPT 1

#define SECRET 3

#define PAD 4

//maximum size we will work with , this should just be text or small files not anything massive
#define MAX_SIZE_BYTES 4096


//internal state

int mode = 0;
int operation = 0;
char secret[MAX_SIZE_BYTES];
char pad[MAX_SIZE_BYTES];

int main(int argc, char **argv) {
    chip_security_checks();
    os_security_checks();
    int arg_no = 1;
    argc--; // Cut off the first arg
    while (argc-- != 0) {
        handle_arg(argv[arg_no], arg_no);
        arg_no++;
    }


    return 0;
}


void handle_arg(char *arg, int arg_no) {

    switch (arg_no) {
        case MODE :

            if(strncmp(arg,"caesar",16) == 0){

                 mode = CAESAR;

            }else if (strncmp(arg,"bits",16) == 0){

                mode = BITS;

            } else{

                printf("An unknown value was passed for mode, acceptable options are 'caesar' or 'bits'");
                exit(1);

            }

            break;

        case OPERATION:

            if(strncmp(arg,"encrypt",16) == 0){

                operation = ENCRYPT;

            }else if (strncmp(arg,"decrypt",16) == 0){

                operation = DECRYPT;

            } else{

                printf("An unknown value was passed for operation, acceptable options are 'encrypt' or 'decrypt'");
                exit(1);

            }

            break;

        case SECRET:
            strncpy(secret,arg,MAX_SIZE_BYTES);
            break;

        case PAD:

            strncpy(secret,arg,MAX_SIZE_BYTES);

            if((strnlen(secret,MAX_SIZE_BYTES) != strnlen(pad,MAX_SIZE_BYTES))){
                printf("The provided secret and pad are not the same length, OTP only works with a key as long as the secret");
                exit(1);
            }
            break;

        default:
            printf("Unknown arg number encountered in handle_arg, exiting...");
            exit(1);

    }

}
void warn_user(char *warning){
    printf("WARN:%s!\n",warning);
}

void os_security_checks(){
#ifdef __WIN32__
    warn_user("BE WARY USING A WINDOWS MACHINE! IT IS NOT SECURE!");
#elifdef __WIN64__
    warn_user("BE WARY USING A WINDOWS MACHINE! IT IS NOT SECURE!");
#elifdef __APPLE__
    warn_user("BE WARY USING A MAC MACHINE! IT IS NOT SECURE!");
#elifdef __ANDROID__
    warn_user("BE WARY USING AN ANDROID MACHINE! IT IS NOT SECURE!");
#endif
}

void chip_security_checks(){
#ifdef __X86_64__
    warn_user("BE WARY USING A MODERN INTEL/AMD CHIP! THERE IS A KNOWN MANAGEMENT ENGINE BACKDOOR!");
#elifdef __aarch64__
    warn_user("BE WARY USING A MODERN ARM CHIP! THERE IS A KNOWN MANAGEMENT ENGINE BACKDOOR IN MANY VENDORS CHIPS!");
#endif
}


