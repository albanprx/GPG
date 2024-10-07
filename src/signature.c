#include <stdio.h>
#include <stdlib.h>
#include <gpgme.h>
#include "../include/main.h"
#include "../include/signature.h"
#include "../include/generation.h"

void sign_file(const char *file_path, FILE *output_file, char *fingerprintsigner)
{
    // GPGME context and error variables
    gpgme_ctx_t ctx;
    gpgme_error_t err;

    // GPGME key and data objects
    gpgme_key_t key;
    gpgme_data_t in, out;

    // Create a new GPGME context
    err = gpgme_new(&ctx);
    check_error(err);

    // Set ASCII-armor mode
    gpgme_set_armor(ctx, 1);

    err = gpgme_data_new_from_file(&in, file_path,1);
    check_error(err);

    err = gpgme_data_new_from_stream(&out, output_file);

    // Retrieve the signing key
    err = gpgme_get_key(ctx, fingerprintsigner, &key, 0);
    check_error(err);

    // Sign the input data and write the signature to the output data object
    err = gpgme_op_sign(ctx, in, out, GPGME_SIG_MODE_DETACH);
    check_error(err);

    gpgme_data_release(in);
    gpgme_key_unref(key);
    gpgme_release(ctx);
}

void sign_and_encrypt_file(const char *file_path, FILE *output_file, char *fingerprint_signer, char *fingerprint_recipient) {
    gpgme_ctx_t ctx;
    gpgme_error_t err;

    gpgme_key_t signer_key, recipient_key;
    gpgme_data_t in, out;

    // Create a new GPGME context
    err = gpgme_new(&ctx);
    check_error(err);

    // Set ASCII-armor mode
    gpgme_set_armor(ctx, 1);

    // Create a new GPGME data object from the input file
    err = gpgme_data_new_from_file(&in, file_path, 1);
    check_error(err);

    // Create a new GPGME data object for the output data
    err = gpgme_data_new_from_stream(&out, output_file);
    check_error(err);

    // Retrieve the signing key
    err = gpgme_get_key(ctx, fingerprint_signer, &signer_key, 0);
    check_error(err);

    // Retrieve the recipient key
    err = gpgme_get_key(ctx, fingerprint_recipient, &recipient_key, 0);
    check_error(err);

    // Encrypt and sign the input data
    gpgme_key_t recipient[2] = {recipient_key, NULL}; // NULL-terminated array of recipient keys
    err = gpgme_op_encrypt_sign(ctx, recipient, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    check_error(err);

    // Clean up
    gpgme_data_release(in);
    gpgme_data_release(out);
    gpgme_key_unref(signer_key);
    gpgme_key_unref(recipient_key);
    gpgme_release(ctx);
}
