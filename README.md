# Context 

This project is for educational purposes only. It is not intended for use in real-world cryptographic applications. Do not use this implementation for securing sensitive data.

# GPG User Guide

# Command to Launch the Program

## Compilation

To compile the program we can use this command:

make

## To get some help:

./GPG -h

## To generate keys:

./GPG -g

## To consult keys in the keychain :

./GPG -l

## To export keys :

./GPG -e <KEY_ID>

### Example :

./GPG -e 684F9D6FA90D3F075F8B9A3BB4C77B0FC67A96C3

./GPG -e 684F9D6FA90D3F075F8B9A3BB4C77B0FC67A96C3 -o ./tests/keys_export.txt

## To import keys :

./GPG -i <file_name>

### Example :

./GPG -i ./tests/keys_export.txt

## To cipher :

./GPG -c <file_name> -r <KEY_ID>

### Example :

./GPG -c ./tests/email.txt -r 684F9D6FA90D3F075F8B9A3BB4C77B0FC67A96C3

./GPG -c ./tests/email.txt -r 684F9D6FA90D3F075F8B9A3BB4C77B0FC67A96C3 -o ./tests/email_cipher.txt

## To decipher :

./GPG -d <file_name>

### Example :

./GPG -d ./tests/email_cipher.txt

./GPG -d ./tests/email_cipher.txt -o ./tests/email_decipher.txt

## To sign :

./GPG -s <file_name> -m <KEY_ID>

### Example :

./GPG -s ./tests/email.txt -m 684F9D6FA90D3F075F8B9A3BB4C77B0FC67A96C3

./GPG -s ./tests/email.txt -m 684F9D6FA90D3F075F8B9A3BB4C77B0FC67A96C3 -o ./tests/email_signer.txt

## To verify :

./GPG -v <file_name> -t <file_name>

### Example :

./GPG -v ./tests/email_signer.txt -t ./tests/email.txt

## To sign and cipher :

./GPG -c <file_name> -r <KEY_ID> -s <file_name> -m <KEY_ID>

### Example :

./GPG -c ./tests/email.txt -r 684F9D6FA90D3F075F8B9A3BB4C77B0FC67A96C3 -s ./tests/email.txt -m 684F9D6FA90D3F075F8B9A3BB4C77B0FC67A96C3

./GPG -c ./tests/email.txt -r 684F9D6FA90D3F075F8B9A3BB4C77B0FC67A96C3 -s ./tests/email.txt -m 684F9D6FA90D3F075F8B9A3BB4C77B0FC67A96C3 -o ./tests/email_cipher_signer.txt

## To decipher and verify :

./GPG -d <file_name>

### Example :

./GPG -d ./tests/email_cipher_signer.txt
