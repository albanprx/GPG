#include <stdio.h>
#include <stdlib.h>
#include <gpgme.h>
#include "../include/main.h"
#include "../include/decipher.h"

void decipher_file(FILE *output, char *filename)
{   
    // GPGME context and error variables
    gpgme_ctx_t ctx;
    gpgme_error_t err;

    // Create a new GPGME context
    err = gpgme_new(&ctx);
    check_error(err);

    // Set the context to use ASCII armor
    gpgme_set_armor(ctx, 1);

    //Create a new GPGME data object from the input file
    gpgme_data_t cipher;
    err = gpgme_data_new_from_file(&cipher, filename, 1);
    check_error(err);

    //Create a new GPGME data object from the output file
    gpgme_data_t plain;
    err = gpgme_data_new_from_stream(&plain, output);
    check_error(err);

    //Decrypt the file and verify the signature
    err = gpgme_op_decrypt_verify(ctx, cipher, plain);
    check_error(err);

    //Get the result of the signature
    gpgme_verify_result_t result;
    result = gpgme_op_verify_result(ctx);
    if (!result)
    {
        printf("Verification result is NULL\n");
        gpgme_data_release(plain);
        gpgme_data_release(cipher);
        gpgme_release(ctx);
        return;
    }

    // Check all signatures in the result
    gpgme_signature_t sigs = result->signatures;
    while (sigs)
    {
        // Check if the key has been revoked
        if (sigs->summary & GPGME_SIGSUM_KEY_REVOKED)
        {
            printf("The key has been revoked.\n");
        }

        // Check if the signature is expired
        if (sigs->summary & GPGME_SIGSUM_KEY_EXPIRED)
        {
            printf("The key has expired.\n");
        }

        // Check if the signature has expired
        if (sigs->summary & GPGME_SIGSUM_SIG_EXPIRED)
        {
            printf("The signature has expired.\n");
        }
        // Check if the signature is valid
        if (sigs->summary & GPGME_SIGSUM_VALID)
        {
            printf("\n\nGood signature\n");
        }
        else
        {
            printf("\n\nThe signature is not verified\n");
        }
        // Move to the next signature
        sigs = sigs->next;
    }
    //Clean up
    gpgme_data_release(plain);
    gpgme_data_release(cipher);
    gpgme_release(ctx);
}