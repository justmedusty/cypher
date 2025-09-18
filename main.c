#include <stdint.h>
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

void parse_secret(char *secret);

#define MODE 1 // the encrypt / decrypt mode IE caesar or raw bits
#define OPERATION 2
#define SECRET 3
#define PAD 4


#define CAESAR 0
#define BITS 1

#define ENCRYPT 0
#define DECRYPT 1
//maximum size we will work with , this should just be text or small files not anything massive
#define MAX_SIZE_BYTES 4096

#define SETTINGS_FILE "/etc/keymaker.conf"


#define OUTPUT_TERMINAL 0
#define OUTPUT_FILE 1

char hex_chars[16] = {
    '0', 1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

//internal state
size_t length = 0;
int output_mode = OUTPUT_TERMINAL;
int mode = 0;
int operation = 0;
char secret[MAX_SIZE_BYTES];
char pad[MAX_SIZE_BYTES];
char output[MAX_SIZE_BYTES];

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
        case MODE:

            if (strncmp(arg, "caesar", 16) == 0) {
                mode = CAESAR;
                printf("Caesar cipher is not yet implemented.\n");
                exit(0);
            } else if (strncmp(arg, "bits", 16) == 0) {
                mode = BITS;
            } else {
                printf("An unknown value was passed for mode, acceptable options are 'caesar' or 'bits'");
                exit(1);
            }

            break;

        case OPERATION:

            if (strncmp(arg, "encrypt", 16) == 0) {
                operation = ENCRYPT;
            } else if (strncmp(arg, "decrypt", 16) == 0) {
                operation = DECRYPT;
            } else {
                printf("An unknown value was passed for operation, acceptable options are 'encrypt' or 'decrypt'");
                exit(1);
            }

            break;

        case SECRET:
            parse_secret(arg);
            break;

        case PAD:

            strncpy(secret, arg,MAX_SIZE_BYTES);

            if ((strnlen(secret,MAX_SIZE_BYTES) != strnlen(pad,MAX_SIZE_BYTES))) {
                printf(
                    "The provided secret and pad are not the same length, OTP only works with a key as long as the secret");
                exit(1);
            }
            length = strlen(secret);
            break;

        default:
            printf("Unknown arg number encountered in handle_arg, exiting...");
            exit(1);
    }
}

void handle_output() {
    if (output_mode == OUTPUT_TERMINAL) {
        printf("%s\n", output);
    } else if (output_mode == OUTPUT_FILE) {
        FILE *f = fopen(SETTINGS_FILE, "rw");
        if (f == NULL) {
            printf("Unable to open settings file");
            exit(1);
        }
        fseek(f, 0, SEEK_END);
        fwrite(output, sizeof(char),MAX_SIZE_BYTES, f);
    }
}

void warn_user(char *warning) {
    printf("WARN:%s!\n", warning);
}

void os_security_checks() {
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

void chip_security_checks() {
#ifdef __X86_64__
    warn_user("BE WARY USING A MODERN INTEL/AMD CHIP! THERE IS A KNOWN MANAGEMENT ENGINE BACKDOOR!");
#elifdef __aarch64__
    warn_user("BE WARY USING A MODERN ARM CHIP! THERE IS A KNOWN MANAGEMENT ENGINE BACKDOOR IN MANY VENDORS CHIPS!");
#endif
}


char convert_to_upper_case(char c) {
    if ((c >= 'a' || c <= 'z')) {
        return ((c - 'a') + 'A');
    } else return c;
}

char get_caesar_shit_char(char value, uint8_t shift_value) {
    if (value > 'Z' || value < 'A') {
        if (value >= 'a' && value <= 'z') {
            return (char) ((convert_to_upper_case(value) + shift_value) % 26 + 'A');
        }
    } else if (value >= 'A' && value <= 'Z') {
        return (char) ((value + shift_value) % 26) + 'A';
    }

    printf("Caesar cipher should have only lower or uppercase letters, found invalid character! Exiting...");
    exit(1);
}

void handle_raw_bits() {
    for (size_t i = 0; i < length; i++) {
        output[i] = (char) (secret[i] ^ pad[i]);
    }

    if (operation == ENCRYPT) {
        for (size_t i = 0; i < length; i++) {
            if (i == 0) {
                printf("0x");
            }
            if (output_mode == OUTPUT_TERMINAL) {
                char c = output[i];
                printf("%02X", c);
                continue;
            } else if (output_mode == OUTPUT_FILE) {
                continue;
            }
        }
        return;
    }

    if (operation == DECRYPT) {
        for (size_t i = 0; i < length; i++) {
            /**
             * It is generally intended for this to be a string message, so it will printed out as such.
             * It could be soemthing else, but otp is generally not used for that. Maybe I will add support
             * for hex printing or something for decryption output but for now this will be it.
             */
            if (output[length] != '\0') {
                if (length == MAX_SIZE_BYTES) {
                    output[MAX_SIZE_BYTES - 1] = '\0';
                } else {
                    output[length] = '\0';
                }
            }
            printf("%s", output);
        }
        return;
    }

    printf("This code was not meant to be reached, something is wrong and you should contact the developer\n");
    exit(1);
}

uint8_t convert_two_hex_chars_to_raw_value(const char c[2]) {
    const uint8_t raw_value_1 = c[0];
    const uint8_t raw_value_2 = c[1];

    if ((raw_value_1 < '0' && raw_value_1 > '9' && raw_value_1 < 'A' && raw_value_1 > 'F') || (raw_value_2 < '0' && raw_value_2 > '9' && raw_value_2 < 'A' && raw_value_2 > 'F')) {
        printf("Invalid character detected in convert_two_hex_chars_to_raw_value");
        exit(1);
    }


}


char get_hex_char(uint8_t value) {

    if (value > 0xF) {
        printf("get_hex_char: Value is out of range\n");
        exit(1);
    }
    return hex_chars[value];
}

/*
 *  Secrets will be h
 */
void parse_secret(char *arg) {
    size_t len = strlen(secret);

    /*
     *  The +2 is to account of the 0x and *2 since 1 byte will store 1 hex char which is 4 bits of data
     */
    if (len > ((MAX_SIZE_BYTES * 2) + 2)) {
        printf("Secret is too big\n");
        exit(1);
    }

    if (secret[0] != '0' && secret[1] != 'x') {
        printf("Secret is not hexadecimal or does not have hexadecimal prefix! Exiting.\n");
        exit(1);
    }
    /*
     * Start at 2 to shave off the 0x prefix
     */
    for (size_t i = 2; i < len; i+=2) {
        secret[i] = get_hex_char(arg[i]);
    }

    if (len % 2 != 0) {

    }
}


