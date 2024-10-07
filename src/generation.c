#include <stdio.h>
#include <gpgme.h>
#include <string.h>
#include "../include/main.h"
#include "../include/generation.h"

void strip_newline(char *str)
{
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n')
    {
        str[len - 1] = '\0';
    }
}

void generate_key()
{
    gpgme_ctx_t ctx;              // GPGME context
    gpgme_error_t err;            // GPGME error variable
    gpgme_genkey_result_t result; // Result structure for key generation

    // Create a new GPGME context
    err = gpgme_new(&ctx);
    check_error(err);

    char userid[256]; // Buffer for user ID
    char email[256];  // Buffer for email

    // Prompt user for User ID
    printf("Enter User ID (Name): ");
    if (fgets(userid, sizeof(userid), stdin) == NULL)
    {
        fprintf(stderr, "Error reading UserID from input.\n");
        gpgme_release(ctx);
        return;
    }

    strip_newline(userid); // Remove newline character from input

    // Prompt user for email
    printf("Enter Email: ");
    if (fgets(email, sizeof(email), stdin) == NULL)
    {
        fprintf(stderr, "Error reading Email from input.\n");
        gpgme_release(ctx);
        return;
    }

    strip_newline(email); // Remove newline character from input

    // Template for key generation parameters
    const char *key_params_template =
        "<GnupgKeyParms format=\"internal\">\n"
        "Key-Type: RSA\n"
        "Key-Length: 3072\n"
        "Key-Usage: sign\n"
        "Subkey-Type: RSA\n"
        "Subkey-Length: 3072\n"
        "Subkey-Usage: encrypt\n"
        "Name-Real: %s\n"
        "Name-Email: %s\n"
        "Expire-Date: 0\n"
        "</GnupgKeyParms>";

    char key_params[1024];                                                        // Buffer for key parameters
    snprintf(key_params, sizeof(key_params), key_params_template, userid, email); // Format key parameters

    // Generate the key pair
    err = gpgme_op_genkey(ctx, key_params, NULL, NULL);
    check_error(err);

    // Get the result of key generation
    result = gpgme_op_genkey_result(ctx);
    if (result->primary)
    {
        printf("Generated primary key with fingerprint: %s\n", result->fpr);
    }
    else
    {
        fprintf(stderr, "Failed to generate primary key.\n");
        return;
    }

    // Release the GPGME context
    gpgme_release(ctx);
}