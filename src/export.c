#include <stdio.h>
#include <stdlib.h>
#include <gpgme.h>
#include "../include/main.h"
#include "../include/export.h"

void export_key(char *fingerprint, FILE *output)
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

    // Create a new GPGME data object from the output file
    gpgme_data_t keydata;
    err = gpgme_data_new_from_stream(&keydata, output);
    check_error(err);

    //Export the public key in the output file
    err = gpgme_op_export(ctx, fingerprint, 0, keydata);
    check_error(err);

    //Clean up
    gpgme_data_release(keydata);
    gpgme_key_unref(key);
    gpgme_release(ctx);
}
