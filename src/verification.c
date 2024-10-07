#include <stdio.h>
#include <stdlib.h>
#include <gpgme.h>
#include "../include/main.h"
#include "../include/verification.h"

void verify_file(const char *file_path, const char *signature_path)
{

    // GPGME context and error variables
    gpgme_ctx_t ctx;
    gpgme_error_t err;

    // GPGME data objects
    gpgme_data_t in, sig;
    gpgme_verify_result_t result;

    // Create a new GPGME context
    err = gpgme_new(&ctx);
    check_error(err);

    // Set the context to use ASCII armor
    gpgme_set_armor(ctx, 1);


    // Create a new GPGME data object from the input file
    err = gpgme_data_new_from_file(&in, file_path, 1);
    check_error(err);

    // Create a new GPGME data object from the signature file
    err = gpgme_data_new_from_file(&sig, signature_path,1 );
    check_error(err);

    // Verify the signature
    err = gpgme_op_verify(ctx, sig, in, NULL);
    check_error(err);

    //Get the result of the signature
    result = gpgme_op_verify_result(ctx);
    if (!result)
    {
        printf("Verification result is NULL\n");
        gpgme_data_release(in);
        gpgme_data_release(sig);
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
            printf("Good signature\n");
        }
        else
        {
            printf("The signature is not verified\n");
        }
        // Move to the next signature
        sigs = sigs->next;
    }

    // Clean up
    gpgme_data_release(in);
    gpgme_data_release(sig);
    gpgme_release(ctx);
}