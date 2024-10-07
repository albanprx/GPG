#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <err.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <gpgme.h>
#include "../include/main.h"
#include "../include/generation.h"
#include "../include/export.h"
#include "../include/import.h"
#include "../include/cipher.h"
#include "../include/decipher.h"
#include "../include/signature.h"
#include "../include/verification.h"

void usage()
{
    printf("Usage : ./GPG -g or -c FILE -r KEYID or -s FILE -m KEYID or -d FILE or -v FILE -t FILE or -l or -h\n");
    printf("-i FILE,  --import FILE       : Import public key from FILE\n");
    printf("-e KEYID, --export KEYID      : Export public key KEYID\n");
    printf("-g,       --generation        : Generate key pair\n");
    printf("-l,       --list              : List of available public keys\n");
    printf("-c FILE,  --cipher FILE       : Cipher FILE\n");
    printf("-r KEYID, --recipient KEYID   : Recipient KEYID \n");
    printf("-d FILE,  --decipher FILE     : Decipher FILE\n");
    printf("-s FILE,  --signature FILE    : Sign FILE\n");
    printf("-m KEYID, --signer KEYID      : KEYID of signer (required for signing)\n");
    printf("-v FILE,  --verification FILE : Verify signature in FILE\n");
    printf("-t FILE,  --text FILE         : Original text (required for signing unless you decipher it at the same time)\n");
    printf("-o FILE,  --output FILE       : Display in FILE\n");
    printf("-h,       --help              : Display this help and exit\n");
}

void init_gpgme()
{
    setlocale(LC_ALL, "");
    gpgme_check_version(NULL);
    gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
    gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
}

void check_error(gpgme_error_t err)
{
    if (err)
    {
        fprintf(stderr, "GPGME error: %s\n", gpgme_strerror(err));
        exit(EXIT_FAILURE);
    }
}

void list_public_keys()
{
    // GPGME context and error variables
    gpgme_ctx_t ctx;
    gpgme_error_t err;

    // Create a new GPGME context
    err = gpgme_new(&ctx);
    check_error(err);

    //Go to the beginning of the key list
    err = gpgme_op_keylist_start(ctx, NULL, 0);
    check_error(err);

    //Show all public keys
    gpgme_key_t key;
    while (!(err = gpgme_op_keylist_next(ctx, &key)))
    {
        check_error(err);
        printf("pub %s\n", key->fpr);
        printf("uid %s <%s>\n", key->uids->name, key->uids->email);
        printf("\n");
        
        //Release the reference to the key
        gpgme_key_unref(key);
    }
    //Get out of the key list
    gpgme_op_keylist_end(ctx);

    gpgme_release(ctx);
}

int main(int argc, char *argv[])
{
    bool is_import = false;
    bool is_export = false;
    bool is_generation = false;
    bool is_cipher = false;
    bool is_decipher = false;
    bool is_signature = false;
    bool is_verification = false;
    bool is_signer = false;
    bool is_text = false;
    char *output_file = NULL;
    char *file_to_sign = NULL;
    char *text_file = NULL;
    char *signature_file = NULL;
    FILE *output = stdout;
    FILE *text = stdout;
    FILE *sign = stdout;
    int opt = 0;
    char *fingerprint;
    char *fingerprint_signer;
    char *fingerprint_recipient;
    char *filename;
    bool list_keys;

    const char *const short_opts = "hi:e:glc:d:s:v:o:m:t:r:";
    static struct option long_opts[] = {
        {"help", no_argument, 0, 'h'},
        {"import", required_argument, 0, 'i'},
        {"export", required_argument, 0, 'e'},
        {"generation", no_argument, 0, 'g'},
        {"list", no_argument, 0, 'l'},
        {"cipher", required_argument, 0, 'c'},
        {"decipher", required_argument, 0, 'd'},
        {"signature", required_argument, 0, 's'},
        {"signer", required_argument, 0, 'm'},
        {"verification", required_argument, 0, 'v'},
        {"recipient", required_argument, 0, 'r'},
        {"text", required_argument, 0, 't'},
        {"output", required_argument, 0, 'o'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case 'i':
            filename = optarg;
            is_import = true;
            break;
        case 'e':
            fingerprint = optarg;
            is_export = true;
            break;
        case 'g':
            is_generation = true;
            break;
        case 'l':
            list_keys = true;
            break;
        case 'c':
            filename = optarg;
            is_cipher = true;
            break;
        case 'd':
            filename = optarg;
            is_decipher = true;
            break;
        case 's':
            file_to_sign = optarg;
            is_signature = true;
            break;
        case 'm':
            fingerprint_signer = optarg;
            is_signer = true;
            break;
        case 'r':
            fingerprint_recipient = optarg;
            break;
        case 'v':
            signature_file = optarg;
            sign = fopen(signature_file, "r");
            if (!sign)
            {
                errx(EXIT_FAILURE, "Unable to open file: %s\n", signature_file);
            }
            is_verification = true;
            break;
        case 't':
            text_file = optarg;
            text = fopen(text_file, "r");
            if (!text)
            {
                errx(EXIT_FAILURE, "Unable to open file: %s\n", text_file);
            }
            is_text = true;
            break;
        case 'o':
            output_file = optarg;
            output = fopen(output_file, "w");
            if (!output)
            {
                errx(EXIT_FAILURE, "Unable to open file: %s\n", output_file);
            }
            break;

        default:
            fprintf(stderr, "Unexpected option\n");
            usage();
            exit(EXIT_FAILURE);
        }
    }

    init_gpgme();
    if (is_generation)
    {
        generate_key();
    }
    if (is_export)
    {
        export_key(fingerprint, output);
    }
    if (is_signature) 
    {
        if (is_signer) 
        {
            if (file_to_sign != NULL) 
            {
                if (is_cipher) 
                {
                sign_and_encrypt_file(file_to_sign, output, fingerprint_signer, fingerprint_recipient);
                }
                else 
                {        
                sign_file(file_to_sign, output, fingerprint_signer);
                }
            }
            else 
            {
                fprintf(stderr, "No file specified for signature.\n");
                usage();
                exit(EXIT_FAILURE);
            }
        }
        else 
        {
            fprintf(stderr, "No signer specified for signature.\n");
            usage();
            exit(EXIT_FAILURE);
        }
    }
    if (is_verification)
    {
        if (is_text)
        {
            verify_file(text_file, signature_file);
        }
        else
        {
            fprintf(stderr, "No signer specified for verification.\n");
            usage();
            exit(EXIT_FAILURE);
        }
    }
    if (list_keys)
    {
        list_public_keys();
    }
    if (is_import)
    {
        import_key(filename);
    }
    if (is_cipher && !is_signature)
    {
        cipher_file(fingerprint_recipient, output, filename);
    }
    if (is_decipher && !is_verification)
    {
        decipher_file(output, filename);
    }
    fclose(output);
    fclose(sign);
    fclose(text);
    return 0;
}
