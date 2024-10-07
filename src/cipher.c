#include <stdio.h>
#include <stdlib.h>
#include <gpgme.h>
#include "../include/main.h"
#include "../include/cipher.h"

void cipher_file(char *fingerprint, FILE *output, char *filename)
{
    // GPGME context and error variables
    gpgme_ctx_t ctx;
    gpgme_error_t err;

    // Create a new GPGME context
    err = gpgme_new(&ctx);
    check_error(err);

    // Set the context to use ASCII armor
    gpgme_set_armor(ctx, 1);

    //Verify the existence of the key
    gpgme_key_t key;
    err = gpgme_get_key(ctx, fingerprint, &key, 0);
    check_error(err);

    //Create a new GPGME data object from the input file
    gpgme_data_t plain;
    err = gpgme_data_new_from_file(&plain, filename, 1);
    check_error(err);

    //Create a new GPGME data object from the output file
    gpgme_data_t cipher;
    err = gpgme_data_new_from_stream(&cipher, output);
    check_error(err);

    //Encrypt the input file, store the result in the output file 
    gpgme_key_t keys[] = {key, NULL};
    err = gpgme_op_encrypt(ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, plain, cipher);
    check_error(err);

    //Clean up
    gpgme_data_release(plain);
    gpgme_data_release(cipher);
    gpgme_key_unref(key);
    gpgme_release(ctx);
}
