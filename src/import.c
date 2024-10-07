#include <stdio.h>
#include <stdlib.h>
#include <gpgme.h>
#include "../include/main.h"
#include "../include/import.h"

void import_key(char *filename)
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
    gpgme_data_t keydata;
    err = gpgme_data_new_from_file(&keydata, filename, 1);
    check_error(err);

    //Import the public key in the keyring
    err = gpgme_op_import(ctx, keydata);
    check_error(err);

    //Clean up
    gpgme_data_release(keydata);
    gpgme_release(ctx);
}