#ifndef SIGNATURE_H
#define SIGNATURE_H
#include <stdio.h>
#include "../include/main.h"

void sign_file(const char *file_path, FILE *output_file, char *fingerprintsigner);
void sign_and_encrypt_file(const char *file_path, FILE *output_file, char *fingerprintsigner, char *recipient_fingerprint);
#endif /* SIGNATURE_H */