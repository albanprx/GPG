#ifndef MAIN_H
#define MAIN_H
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

void init_gpgme();
void check_error(gpgme_error_t err);
void list_public_keys();

#endif /* MAIN_H */
