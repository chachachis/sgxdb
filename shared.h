// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H

#define HASH_VALUE_SIZE_IN_BYTES 32 // sha256 hashing algorithm
#define ENCRYPTION_KEY_SIZE 256     // AES256-CBC encryption algorithm
#define ENCRYPTION_KEY_SIZE_IN_BYTES (ENCRYPTION_KEY_SIZE / 8)
#define IV_SIZE 16 // determined by AES256-CBC
#define SALT_SIZE_IN_BYTES IV_SIZE
#define MAX_SEQ_SIZE 1024

// encryption_header_t contains encryption metadata used for decryption
// file_data_size: this is the size of the data in an input file, excluding the
// header digest: this field contains hash value of a password
// encrypted_key: this is the encrypted version of the encryption key used for
//                encrypting and decrypting the data
// salt: The salt value used in deriving the password key.
//       It is also used as the IV for the encryption/decryption of the data.
typedef struct _encryption_header
{
    size_t file_data_size;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES];
    unsigned char encrypted_key[ENCRYPTION_KEY_SIZE_IN_BYTES];
    unsigned char salt[SALT_SIZE_IN_BYTES];
} encryption_header_t;

typedef struct {
	int major;
	int minor;
} model_id_t;

typedef struct {
	model_id_t id;
	int reverse_complement;
	int num_detectors;
	int detector_len;
	int has_avg_pooling;
	int num_hidden;
	float* detectors;
	float* thresholds;
	float* weights1;
	float* biases1;
	float* weights2;
	float* biases2;
} deepbind_model_t;

#endif /* _ARGS_H */
