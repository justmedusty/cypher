
/*
Cypher : a cli tool for encrypting and decrypting secret messages using OTP, intended for relatively short ascii messages
Copyright (C) 2025 Dustyn Gibb

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA

*/
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "stdlib.h"

void handle_arg(char* arg, int arg_no);
void chip_security_checks();
void handle_output();
void os_security_checks();
void parse_pad(char* arg);
void parse_secret(char* arg);
void handle_raw_bits();

#define OPERATION 1
#define SECRET 2
#define PAD 3

#define NUM_ARGS 4

#define ENCRYPT 0
#define DECRYPT 1
//maximum size we will work with , this should just be text or small files not anything massive
#define MAX_SIZE_BYTES 4096

#ifdef _DEBUG_
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...) ((void)0)
#endif

char hex_chars[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

//internal state
size_t length = 0;
int operation = 0;
char secret[MAX_SIZE_BYTES] = {0};
char pad[MAX_SIZE_BYTES] = {0};
char output[MAX_SIZE_BYTES] = {0};

void help() {
    printf(
        "\nUsage: keymaker encrypt/decrypt \"secret\" pad\nPad must start with 0x and be in HEXADECIMAL FORMAT!\nIf secret is encrypted, it also MUST BE IN HEXADECIMAL FORMAT!\n");
    exit(0);
}

int main(int argc, char** argv) {
    chip_security_checks();
    os_security_checks();

    if (argc != NUM_ARGS) {
        help();
    }
    int arg_no = 1;
    argc--; // Cut off the first arg
    while (argc-- != 0) {
        handle_arg(argv[arg_no], arg_no);
        arg_no++;
    }

    handle_raw_bits();
    return 0;
}


void handle_arg(char* arg, int arg_no) {
    switch (arg_no) {
    case OPERATION:

        if (strncmp(arg, "encrypt", 16) == 0) {
            operation = ENCRYPT;
        }
        else if (strncmp(arg, "decrypt", 16) == 0) {
            operation = DECRYPT;
        }
        else {
            printf("An unknown value was passed for operation, acceptable options are 'encrypt' or 'decrypt'\n");
            help();
            exit(1);
        }

        break;

    case SECRET:
        parse_secret(arg);
        break;

    case PAD:
        parse_pad(arg);
        break;

    default:
        printf("Unknown arg number encountered in handle_arg, exiting...\n");
        help();
        exit(1);
    }
}

void warn_user(char* warning) {
    printf("WARN:%s!\n", warning);
}

void os_security_checks() {
#ifdef __WIN32__
    warn_user("Be wary using a windows machine, it is inherently insecure!");
#elifdef __WIN64__
    warn_user("Be wary using a windows machine, it is inherently insecure!");
#elifdef __APPLE__
    warn_user("Be wary using a mac machine, it is inherently insecure!");
#elifdef __ANDROID__
    warn_user("Be wary using a windows machine, it is inherently insecure!");
#endif
}

void chip_security_checks() {
#ifdef __x86_64__
    warn_user(
        "Be wary using modern intel or amd chips, they have a known management engine backdoor. If this secret is of life or death stakes, do not use this machine");
#elifdef __aarch64__
    warn_user(
        "Be wary using modern arm chips, many of them have a known management engine backdoor. If this secret is of life or death stakes, do not use this machine");
#endif
}

void handle_raw_bits() {
    DEBUG_PRINT("handle_raw_bits: length : %lu\n", length);
    for (size_t i = 0; i < length; i++) {
        output[i] = (char)(secret[i] ^ pad[i]);
    }
    output[length] = '\0';

    if (operation == ENCRYPT) {

        DEBUG_PRINT("handle_raw_bits: ENCRYPT branch: Length is %lu\n", length);
        printf("0x");
        for (size_t i = 0; i < length; i++) {
            const char c = output[i];
            printf("%02X", c & 0xFF);
            fflush(stdout);
        }
        printf("\n");
        return;
    }

    if (operation == DECRYPT) {
        /**
         * It is generally intended for this to be a string message, so it will printed out as such.
         * It could be soemthing else, but otp is generally not used for that. Maybe I will add support
         * for hex printing or something for decryption output but for now this will be it.
         */
        if (output[length] != '\0') {
            DEBUG_PRINT("Entered output \0 branch in decrypt output\n");
            if (length == MAX_SIZE_BYTES) {
                output[MAX_SIZE_BYTES - 1] = '\0';
            }
            else {
                output[length] = '\0';
            }
        }
        printf("Secret: %s\n", output);

        return;
    }

    printf("This code was not meant to be reached, something is wrong and you should contact the developer\n");
    exit(1);
}

uint8_t hex_char_to_int(const char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    printf("Hex character is not a valid hexadecimal character! Char : %lu\n", (uint64_t)c);
    exit(1);
}

uint8_t convert_two_hex_chars_to_raw_value(const char c[2]) {
    const uint8_t raw_value_1 = hex_char_to_int(c[0]);
    const uint8_t raw_value_2 = hex_char_to_int(c[1]);

    return raw_value_1 << 4 | raw_value_2;
}

char get_hex_char_from_raw_value(const uint8_t value) {
    if (value > 0xF) {
        printf("get_hex_char: Value is out of range\n");
        help();
        exit(1);
    }
    return hex_chars[value];
}

/*
 *  Secrets will be h
 */
void parse_secret(char* arg) {
    size_t len = strlen(arg);
    if (operation == ENCRYPT) {
        for (size_t i = 0; i < len; i++) {
            secret[i] = arg[i];
        }
        length = len;
        return;
    }

    /*
     *  The +2 is to account of the 0x and *2 since 1 byte will store 1 hex char which is 4 bits of data
     */
    if (len > ((MAX_SIZE_BYTES * 2) + 2)) {
        printf("Secret is too big, it must match the size of the pad\n");
        exit(1);
    }

    if (arg[0] != '0' && arg[1] != 'x') {
        printf("Encrypted secret is not hexadecimal or does not have hexadecimal prefix! Exiting.\n");
        help();
        exit(1);
    }
    /*
     * Start at 2 to shave off the 0x prefix
     */
    uint64_t secret_index = 0;

    for (size_t i = 2; i < len; i += 2) {
        secret[secret_index++] = convert_two_hex_chars_to_raw_value(&arg[i]);
    }

    if (len % 2 != 0) {
        secret[secret_index++] = hex_char_to_int(arg[len - 1]);
    }

    length = secret_index;
}

void parse_pad(char* arg) {
    /*
  *  The +2 is to account of the 0x and *2 since 1 byte will store 1 hex char which is 4 bits of data
  */
    uint64_t len = strlen(arg);
    if (len > ((MAX_SIZE_BYTES * 2) + 2)) {
        printf("Pad is too big, max size is 4096 bytes\n");
        exit(1);
    }

    if (len - 2 < (length * 2)) {
        printf("Pad is too short! Exiting...\n");
        exit(1);
    }

    if (arg[0] != '0' && arg[1] != 'x') {
        printf("Pad is not hexadecimal or does not have hexadecimal prefix! Exiting. Arg is %s\n", arg);
        help();
        exit(1);
    }

    /*
    * Start at 2 to shave off the 0x prefix
    */
    uint64_t pad_index = 0;




    for (size_t i = 2; i < length * 2; i += 2) {
        if (i + 1 == length * 2) {
            pad[pad_index++] = hex_char_to_int(arg[i]);
            break;
        }
        pad[pad_index++] = convert_two_hex_chars_to_raw_value(&arg[i]);
    }

    if (length % 2 != 0) {
        if (pad_index == len / 2) {
            printf("Pad is too short!");
            help();
            exit(1);
        }
        pad[pad_index++] = hex_char_to_int(arg[length - 1]);
    }

    DEBUG_PRINT("parse_pad: pad_index is %lu while length is %lu\n", pad_index, length);

}


