// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define _CRT_SECURE_NO_WARNINGS
#include <assert.h>
#include <limits.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include "../shared.h"

#include "fileencryptor_u.h"

using namespace std;

#define CIPHER_BLOCK_SIZE 16
#define DATA_BLOCK_SIZE 256
#define ENCRYPT_OPERATION true
#define DECRYPT_OPERATION false

static string operation;
static oe_enclave_t* enclave = NULL;

const char* DIRECTORY_OF_PARAMETERS = "C:/sgxdb/db/params/";

/* create new "deepbind" class in enclave directory,
add deepbind to cmakelists

deepbind code:
1. check + parse command line for file names
2. malloc for model_id* 

 */

// host helper functions

void hcall_printscores(float* scores, size_t modelcount) {
    for (size_t i = 0; i < modelcount; i++) {
        if (i > 0) {
            fputc('\t', stdout);
        }
        fprintf(stdout, "%f", double(scores[i]));
    }
    fputc('\n', stdout);
}

void printusage(const char* prog) {
    cerr << "Usage: " << prog 
        << " model-ids-file sequences-file enclave_image_path [ --simulate  ]" << endl;
}

void trim_trailing_whitespace(char* str)
{
	int i = (int)strlen(str);
	while (i > 0 && (str[i - 1] == '\n' || str[i - 1] == ' ' || str[i - 1] == '\t' || str[i - 1] == '\r'))
		i--;
	str[i] = '\0';
}

int get_num_hidden1(deepbind_model_t* model) { return model->has_avg_pooling ? model->num_detectors * 2 : model->num_detectors; }
int get_num_hidden2(deepbind_model_t* model) { return model->num_hidden ? model->num_hidden : 1; }

model_id_t str2id(char* str)
{
	model_id_t id = { 0, 0 };
	char tmp[6];
	if (!str) {
		cout << "Invalid model id NULL";
        exit(-1);
    }
	if (strlen(str) < 10 || str[0] != 'D' || str[6] != '.') {
		cout << "Invalid model id \"\"; should be of form D#####.###" << str;
        exit(-1);
    }
	memcpy(tmp, str + 1, 5); tmp[5] = '\0';
	id.major = atoi(tmp);
	id.minor = atoi(str + 7);
	if (id.major <= 0 || id.minor <= 0) {
        cout << "Invalid model id " << str << "; should be of form DXXXXX.YYY where XXXXX >= 1 and YYY >= 1";
		exit(-1);
    }
    
	return id;
}

void id2str(model_id_t id, char* dst)
{
	if (id.major <= 0 || id.minor <= 0) {
		cout << "Invalid model id";
        exit(-1);
    }
	sprintf(dst, "D%05d.%03d", id.major, id.minor);
}

void panic(const char* msg, ...)
{
	va_list va;
	va_start(va, msg);
	vprintf(msg, va);
	va_end(va);
	printf("\n");
	exit(-1);
}

bool check_simulate_opt(int* argc, const char* argv[])
{
    for (int i = 0; i < *argc; i++)
    {
        if (strcmp(argv[i], "--simulate") == 0)
        {
            cout << "Running in simulation mode" << endl;
            memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
            (*argc)--;
            return true;
        }
    }
    return false;
}

// Dump Encryption header
void dump_header(encryption_header_t* _header)
{
    cout << "--------- Dumping header -------------\n";
    cout << "Host: fileDataSize = " << _header->file_data_size << endl;

    cout << "Host: password digest:\n";
    for (int i = 0; i < HASH_VALUE_SIZE_IN_BYTES; i++)
    {
        cout << "Host: digest[" << i << "]" << std::hex
             << (unsigned int)(_header->digest[i]) << endl;
    }

    cout << "Host: encryption key" << endl;
    for (int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
    {
        cout << "Host: key[" << i << "]=" << std::hex
             << (unsigned int)(_header->encrypted_key[i]) << endl;
    }

    cout << "Host: salt and IV" << endl;
    for (int i = 0; i < SALT_SIZE_IN_BYTES; i++)
    {
        cout << "Host: salt[" << i << "]=" << std::hex
             << (unsigned int)(_header->salt[i]) << endl;
    }
}

// get the file size
int get_file_size(FILE* file, size_t* _file_size)
{
    int ret = 0;
    long int oldpos = 0;

    oldpos = ftell(file);
    ret = fseek(file, 0L, SEEK_END);
    if (ret != 0)
        goto exit;

    *_file_size = (size_t)ftell(file);
    fseek(file, oldpos, SEEK_SET);

exit:
    return ret;
}

// Compare file1 and file2: return 0 if the first file1.size bytes of the file2
// is equal to file1's contents  Otherwise it returns 1
int compare_2_files(const char* first_file, const char* second_file)
{
    int ret = 0;
    std::ifstream f1(first_file, std::ios::binary);
    std::ifstream f2(second_file, std::ios::binary);
    std::vector<uint8_t> f1_data_bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f1), std::istreambuf_iterator<char>());
    std::vector<uint8_t> f2_data_bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f2), std::istreambuf_iterator<char>());
    std::vector<uint8_t>::iterator f1iterator = f1_data_bytes.begin();
    std::vector<uint8_t>::iterator f2iterator = f2_data_bytes.begin();

    // compare files
    for (; f1iterator != f1_data_bytes.end() - 1; ++f1iterator, ++f2iterator)
    {
        if (!(*f1iterator == *f2iterator))
        {
            ret = 1;
            break;
        }
    }
    cout << "Host: two files are " << ((ret == 0) ? "equal" : "not equal")
         << endl;
    return ret;
}

int encrypt_file(
    bool encrypt,
    const char* password,
    const char* input_file,
    const char* output_file)
{
    oe_result_t result;
    int ret = 0;
    FILE* src_file = NULL;
    FILE* dest_file = NULL;
    unsigned char* r_buffer = NULL;
    unsigned char* w_buffer = NULL;
    size_t bytes_read;
    size_t bytes_to_write;
    size_t bytes_written;
    size_t src_file_size = 0;
    size_t src_data_size = 0;
    size_t leftover_bytes = 0;
    size_t bytes_left = 0;
    size_t requested_read_size = 0;
    encryption_header_t header;

    // allocate read/write buffers
    r_buffer = new unsigned char[DATA_BLOCK_SIZE];
    if (r_buffer == NULL)
    {
        ret = 1;
        goto exit;
    }

    w_buffer = new unsigned char[DATA_BLOCK_SIZE];
    if (w_buffer == NULL)
    {
        cerr << "Host: w_buffer allocation error" << endl;
        ret = 1;
        goto exit;
    }

    // open source and dest files
    src_file = fopen(input_file, "rb");
    if (!src_file)
    {
        cout << "Host: fopen " << input_file << " failed." << endl;
        ret = 1;
        goto exit;
    }

    ret = get_file_size(src_file, &src_file_size);
    if (ret != 0)
    {
        ret = 1;
        goto exit;
    }
    src_data_size = src_file_size;
    dest_file = fopen(output_file, "wb");
    if (!dest_file)
    {
        cerr << "Host: fopen " << output_file << " failed." << endl;
        ret = 1;
        goto exit;
    }

    // For decryption, we want to read encryption header data into the header
    // structure before calling initialize_encryptor
    if (!encrypt)
    {
        bytes_read = fread(&header, 1, sizeof(header), src_file);
        if (bytes_read != sizeof(header))
        {
            cerr << "Host: read header failed." << endl;
            ret = 1;
            goto exit;
        }
        src_data_size = src_file_size - sizeof(header);
    }

    // Initialize the encryptor inside the enclave
    // Parameters: encrypt: a bool value to set the encryptor mode, true for
    // encryption and false for decryption
    // password is provided for encryption key used inside the encryptor. Upon
    // return, _header will be filled with encryption key information for
    // encryption operation. In the case of decryption, the caller provides
    // header information from a previously encrypted file
    result = initialize_encryptor(
        enclave, &ret, encrypt, password, strlen(password), &header);
    if (result != OE_OK)
    {
        ret = 1;
        goto exit;
    }
    if (ret != 0)
    {
        goto exit;
    }

    // For encryption, on return from initialize_encryptor call, the header will
    // have encryption information. Write this header to the output file.
    if (encrypt)
    {
        header.file_data_size = src_file_size;
        bytes_written = fwrite(&header, 1, sizeof(header), dest_file);
        if (bytes_written != sizeof(header))
        {
            cerr << "Host: writting header failed. bytes_written = "
                 << bytes_written << " sizeof(header)=" << sizeof(header)
                 << endl;
            ret = 1;
            goto exit;
        }
    }

    leftover_bytes = src_data_size % CIPHER_BLOCK_SIZE;

    // cout << "Host: leftover_bytes " << leftover_bytes << endl;

    // Encrypt each block in the source file and write to the dest_file. Process
    // all the blocks except the last one if its size is not a multiple of
    // CIPHER_BLOCK_SIZE when padding is needed
    bytes_left = src_data_size;

    if (leftover_bytes)
    {
        bytes_left = src_data_size - leftover_bytes;
    }
    requested_read_size =
        bytes_left > DATA_BLOCK_SIZE ? DATA_BLOCK_SIZE : bytes_left;
    cout << "Host: start " << (encrypt ? "encrypting" : "decrypting") << endl;

    // It loops through DATA_BLOCK_SIZE blocks one at a time then followed by
    // processing the last remaining multiple of CIPHER_BLOCK_SIZE blocks. This
    // loop makes sure all the data is processed except leftover_bytes bytes in
    // the end.
    while (
        (bytes_read = fread(
             r_buffer, sizeof(unsigned char), requested_read_size, src_file)) &&
        bytes_read > 0)
    {
        // Request for the enclave to encrypt or decrypt _input_buffer. The
        // block size (bytes_read), needs to be a multiple of CIPHER_BLOCK_SIZE.
        // In this sample, DATA_BLOCK_SIZE is used except the last block, which
        // will have to pad it to be a multiple of CIPHER_BLOCK_SIZE.
        // Eg. If testfile data size is 260 bytes, then the last block will be
        // 4 data + 12 padding bytes = 16 bytes (CIPHER_BLOCK_SIZE).
        result = encrypt_block(
            enclave, &ret, encrypt, r_buffer, w_buffer, bytes_read);
        if (result != OE_OK)
        {
            cerr << "encrypt_block error 1" << endl;
            ret = 1;
            goto exit;
        }
        if (ret != 0)
        {
            cerr << "encrypt_block error 1" << endl;
            goto exit;
        }

        bytes_to_write = bytes_read;
        // The data size is always padded to align with CIPHER_BLOCK_SIZE
        // during encryption. Therefore, remove the padding (if any) from the
        // last block during decryption.
        if (!encrypt && bytes_left <= DATA_BLOCK_SIZE)
        {
            bytes_to_write = header.file_data_size % DATA_BLOCK_SIZE;
            bytes_to_write = bytes_to_write > 0 ? bytes_to_write : bytes_read;
        }

        if ((bytes_written = fwrite(
                 w_buffer, sizeof(unsigned char), bytes_to_write, dest_file)) !=
            bytes_to_write)
        {
            cerr << "Host: fwrite error  " << output_file << endl;
            ret = 1;
            goto exit;
        }

        bytes_left -= requested_read_size;
        if (bytes_left == 0)
            break;
        if (bytes_left < DATA_BLOCK_SIZE)
            requested_read_size = bytes_left;
    }

    if (encrypt)
    {
        // The CBC mode for AES assumes that we provide data in blocks of
        // CIPHER_BLOCK_SIZE bytes. This sample uses PKCS#5 padding. Pad the
        // whole CIPHER_BLOCK_SIZE block if leftover_bytes is zero. Pad the
        // (CIPHER_BLOCK_SIZE - leftover_bytes) bytes if leftover_bytes is
        // non-zero.
        size_t padded_byte_count = 0;
        unsigned char plaintext_padding_buf[CIPHER_BLOCK_SIZE];
        unsigned char ciphertext_padding_buf[CIPHER_BLOCK_SIZE];

        memset(ciphertext_padding_buf, 0, CIPHER_BLOCK_SIZE);
        memset(plaintext_padding_buf, 0, CIPHER_BLOCK_SIZE);

        if (leftover_bytes == 0)
            padded_byte_count = CIPHER_BLOCK_SIZE;
        else
            padded_byte_count = CIPHER_BLOCK_SIZE - leftover_bytes;

        cout << "Host: Working the last block" << endl;
        cout << "Host: padded_byte_count " << padded_byte_count << endl;
        cout << "Host: leftover_bytes " << leftover_bytes << endl;

        bytes_read = fread(
            plaintext_padding_buf,
            sizeof(unsigned char),
            leftover_bytes,
            src_file);
        if (bytes_read != leftover_bytes)
            goto exit;

        // PKCS5 Padding
        memset(
            (void*)(plaintext_padding_buf + leftover_bytes),
            padded_byte_count,
            padded_byte_count);

        result = encrypt_block(
            enclave,
            &ret,
            encrypt,
            plaintext_padding_buf,
            ciphertext_padding_buf,
            CIPHER_BLOCK_SIZE);
        if (result != OE_OK)
        {
            ret = 1;
            goto exit;
        }
        if (ret != 0)
        {
            goto exit;
        }

        bytes_written = fwrite(
            ciphertext_padding_buf,
            sizeof(unsigned char),
            CIPHER_BLOCK_SIZE,
            dest_file);
        if (bytes_written != CIPHER_BLOCK_SIZE)
            goto exit;
    }

    cout << "Host: done  " << (encrypt ? "encrypting" : "decrypting") << endl;

    // close files
    fclose(src_file);
    fclose(dest_file);

exit:
    delete[] r_buffer;
    delete[] w_buffer;
    cout << "Host: called close_encryptor" << endl;

    result = close_encryptor(enclave);
    if (result != OE_OK)
    {
        ret = 1;
    }
    return ret;
}

// host calls from enclave

int loadmodelids(const char* modelfile) {
    // Parses model-ids-file and adds each id to enclave
    char buffer[1024];
    model_id_t id;
    FILE* file = fopen(modelfile, "r");
    oe_result_t result;
    int count = 0;

    if (!file) {
        cout << "couldnt call " << modelfile;
        exit(-1);
    }

    result = ecall_initmodel(enclave);
    if (result != OE_OK) {
        cout << "Trouble initialising model" << endl;
    }

    while (fgets(buffer, 1024, file)) {
        if (buffer[0] != '#') {
            trim_trailing_whitespace(buffer);
            id = str2id(buffer);
            result = ecall_addIDtomodel(enclave, id.major, id.minor);
            if (result != OE_OK) {
                cout << "Trouble adding id to model via ecall ";
                exit(-1);
            }
            count++;
        }
    }
    return count;
}

void load_model_paramlist(FILE* file, char* param_file, const char* param_name, float** _dst, int num_params)
{
	int i;
	char buffer[64];
	float* dst = 0;
	*_dst = 0;
	strcpy(buffer, param_name);
	if (num_params > 0) {
		float* dst = (float*)malloc(sizeof(float) * num_params);
		strcat(buffer, " = %f");
		if (fscanf(file, buffer, &dst[0]) != 1)
			panic("Failed parsing %s in file %s", param_file, param_name);
		for (i = 1; i < num_params; ++i)
			if (fscanf(file, ",%f", &dst[i]) != 1)
				panic("Failed parsing %s in file %s", param_file, param_name);
		fscanf(file, "\n"); // eat up the carriage return
		*_dst = dst;
	}
	else {
		strcat(buffer, " = ");
		fscanf(file, buffer); // eat up the line
	}
}

int decrypt_file_to_enclave(
    bool encrypt,
    const char* password,
    const char* input_file,
    const char* output_file)
{
    oe_result_t result;
    int ret = 0;
    FILE* src_file = NULL;
    FILE* dest_file = NULL;
    unsigned char* r_buffer = NULL;
    unsigned char* w_buffer = NULL;
    size_t bytes_read;
    size_t bytes_to_write;
    size_t bytes_written;
    size_t src_file_size = 0;
    size_t src_data_size = 0;
    size_t leftover_bytes = 0;
    size_t bytes_left = 0;
    size_t requested_read_size = 0;
    encryption_header_t header;

    // allocate read/write buffers
    r_buffer = new unsigned char[MAX_SEQ_SIZE];
    if (r_buffer == NULL)
    {
        ret = 1;
        goto exit;
    }

    w_buffer = new unsigned char[MAX_SEQ_SIZE];
    if (w_buffer == NULL)
    {
        cerr << "Host: w_buffer allocation error" << endl;
        ret = 1;
        goto exit;
    }

    // open source and dest files
    src_file = fopen(input_file, "rb");
    if (!src_file)
    {
        cout << "Host: fopen " << input_file << " failed." << endl;
        ret = 1;
        goto exit;
    }

    ret = get_file_size(src_file, &src_file_size);
    if (ret != 0)
    {
        ret = 1;
        goto exit;
    }
    src_data_size = src_file_size;
    dest_file = fopen(output_file, "wb");
    if (!dest_file)
    {
        cerr << "Host: fopen " << output_file << " failed." << endl;
        ret = 1;
        goto exit;
    }
    

    // For decryption, we want to read encryption header data into the header
    // structure before calling initialize_encryptor
    bytes_read = fread(&header, 1, sizeof(header), src_file);
    if (bytes_read != sizeof(header))
    {
        cerr << "Host: read header failed." << endl;
        ret = 1;
        goto exit;
    }
    src_data_size = src_file_size - sizeof(header);

    // Initialize the encryptor inside the enclave
    // Parameters: encrypt: a bool value to set the encryptor mode, true for
    // encryption and false for decryption
    // password is provided for encryption key used inside the encryptor. Upon
    // return, _header will be filled with encryption key information for
    // encryption operation. In the case of decryption, the caller provides
    // header information from a previously encrypted file
    result = initialize_encryptor(
        enclave, &ret, DECRYPT_OPERATION, password, strlen(password), &header);
    if (result != OE_OK)
    {
        ret = 1;
        goto exit;
    }
    if (ret != 0)
    {
        goto exit;
    }

    leftover_bytes = src_data_size % CIPHER_BLOCK_SIZE;

    cout << "Host: leftover_bytes " << leftover_bytes << endl;

    // Encrypt each block in the source file and write to the dest_file. Process
    // all the blocks except the last one if its size is not a multiple of
    // CIPHER_BLOCK_SIZE when padding is needed
    bytes_left = src_data_size;

    if (leftover_bytes)
    {
        bytes_left = src_data_size - leftover_bytes;
    }
    requested_read_size =
        bytes_left > MAX_SEQ_SIZE ? MAX_SEQ_SIZE : bytes_left;
    // cout << "Host: start decrypting" << endl;

    // It loops through DATA_BLOCK_SIZE blocks one at a time then followed by
    // processing the last remaining multiple of CIPHER_BLOCK_SIZE blocks. This
    // loop makes sure all the data is processed except leftover_bytes bytes in
    // the end.
    while (
        (bytes_read = fread(
             r_buffer, sizeof(unsigned char), requested_read_size, src_file)) &&
        bytes_read > 0)
    {


        bytes_to_write = bytes_read;
        // The data size is always padded to align with CIPHER_BLOCK_SIZE
        // during encryption. Therefore, remove the padding (if any) from the
        // last block during decryption.
        
        /*
        cout << "bytes to write = " << bytes_to_write << endl;
        if (!encrypt && bytes_left <= DATA_BLOCK_SIZE)
        {
            bytes_to_write = header.file_data_size % DATA_BLOCK_SIZE;
            cout << "bytes to write = " << bytes_to_write << endl;
            bytes_to_write = bytes_to_write > 0 ? bytes_to_write : bytes_read;
            cout << "bytes to write = " << bytes_to_write << endl;
        }
        */

        // cout << "bytes to write = " << bytes_to_write << endl;
        bytes_left -= requested_read_size;
        size_t paddingsize = header.file_data_size % DATA_BLOCK_SIZE;
        result = ecall_decryptpredict(enclave, &ret, r_buffer, w_buffer, bytes_to_write, bytes_left==0, paddingsize);
        // cout << "result from ecall_decryptpredict = " << result << endl;

        if (bytes_left == 0)
            break;
        if (bytes_left < MAX_SEQ_SIZE)
            requested_read_size = bytes_left;
    }

    cout << "Host: done decrypting" << endl;

    // close files
    fclose(src_file);
    fclose(dest_file);

exit:
    delete[] r_buffer;
    delete[] w_buffer;
    cout << "Host: called close_encryptor" << endl;

    result = close_encryptor(enclave);
    if (result != OE_OK)
    {
        ret = 1;
    }
    return ret;
}

deepbind_model_t* load_model(model_id_t id)
{
	char param_file[512];
	int major_version = 0;
	int minor_version = 0;
	deepbind_model_t* model = 0;
	FILE* file = 0;

	/* Find path to file*/
	strcpy(param_file, DIRECTORY_OF_PARAMETERS);
	id2str(id, param_file + strlen(param_file));
	strcat(param_file, ".txt");
    // cout << "param_file to open = " << param_file << endl;

	/* Open the file and parse each line */
	file = fopen(param_file, "r");
	if (!file)
		panic("Could not open param file %s.", param_file);

	if (fscanf(file, "# deepbind %d.%d\n", &major_version, &minor_version) != 2)
		panic("Expected parameter file to start with \"# deepbind 0.1\"");
	if (major_version != 0 || minor_version != 1)
		panic("Param file is for deepbind %d.%d, not 0.1", major_version, minor_version);

	model = (deepbind_model_t*)malloc(sizeof(deepbind_model_t));
	model->id = id;

	if (fscanf(file, "reverse_complement = %d\n", &model->reverse_complement) != 1) panic("Failed parsing reverse_complement in %s", param_file);
	if (fscanf(file, "num_detectors = %d\n", &model->num_detectors) != 1)      panic("Failed parsing num_detectors in %s", param_file);
	if (fscanf(file, "detector_len = %d\n", &model->detector_len) != 1)       panic("Failed parsing detector_len in %s", param_file);
	if (fscanf(file, "has_avg_pooling = %d\n", &model->has_avg_pooling) != 1)    panic("Failed parsing has_avg_pooling in %s", param_file);
	if (fscanf(file, "num_hidden = %d\n", &model->num_hidden) != 1)         panic("Failed parsing num_hidden in %s", param_file);

	load_model_paramlist(file, param_file, "detectors", &model->detectors, model->num_detectors * model->detector_len * 4);
	load_model_paramlist(file, param_file, "thresholds", &model->thresholds, model->num_detectors);
	load_model_paramlist(file, param_file, "weights1", &model->weights1, get_num_hidden1(model) * get_num_hidden2(model));
	load_model_paramlist(file, param_file, "biases1", &model->biases1, get_num_hidden2(model));
	load_model_paramlist(file, param_file, "weights2", &model->weights2, model->num_hidden ? model->num_hidden : 0);
	load_model_paramlist(file, param_file, "biases2", &model->biases2, model->num_hidden ? 1 : 0);

	fclose(file);
	return model;
}

/* Loads model parameters to deepbind model in enclave.
    Also prints headers on stdout.  */
void loadmodelparams(int modelcount) {
    model_id_t modelid;
    deepbind_model_t* model;
    oe_result_t result;

    cout << "Host: Loading parameters onto enclave model.\n";

    for (int i = 0; i < modelcount; i++) {
        result = ecall_getdbmodelid(enclave, &modelid, (size_t) i);
        model = load_model(modelid);
        result = ecall_loadparams(enclave, *model);
        if (result != OE_OK) {
            cout << "error on ecall_loadparams " << i << "\n";
            exit(-1);
        }
        
        if (i > 0) {
            fputc('\t', stdout);
        }
        fprintf(stdout, "D%05d.%03d", modelid.major, modelid.minor);
    }
    fputc('\n', stdout);
}

void printscores(vector<float> scores) {
    int i = 0;

    for (vector<float>::iterator it = scores.begin(); it != scores.end(); it++) {
        if (i > 0) {
            fputc('\t', stdout);
        }
        fprintf(stdout, "%f", (double) *it);
        i++;
    }
    fputc('\n', stdout);
}

void predictseqs(const char* seqfile, int num_models) {
    // Parses sequences-file and calls enclave to obtain predictions

    char buffer[1024]; // maximum length of sequences to predict
    FILE* file = fopen(seqfile, "r");
    oe_result_t result;
    int lineindex = 0;

    if (!file) {
        cout << "error opening file " << seqfile;
        exit(-1);
    }
    
    while(fgets(buffer, 1024, file)) {
        vector<float> scores;
        trim_trailing_whitespace(buffer);
        size_t bufferlen = strlen(buffer);
        if(bufferlen > 0) {
            size_t validseq = 0;
            char* cptr = new char;
            ecall_checkvalidseq(enclave, &validseq, (unsigned char*) buffer, bufferlen);
            if (validseq != 0) {
                cout << "Sequence on line " << lineindex << ", " << validseq << " is not valid.\n";
                exit(-1);
            }

            for (int i = 0; i < num_models; i++) {
                float score;
                result = ecall_scanmodel(enclave, &score, (size_t) i, (unsigned char*) buffer, bufferlen, 0, 0);
                model_id_t modelid;
                result = ecall_getdbmodelid(enclave, &modelid, i);
                scores.push_back(score);
                if (result != OE_OK) {
                    cout << "Result from ecall_scanmodel not ok";
                    exit(-1);
                }
            }
            printscores(scores);
            lineindex++;
        }
    }

}

void run_encrypt(const char* input_file, const char* encrypted_file, const char* pw) {
    
    int ret = 0;
    // encrypt a file
    cout << "Host: encrypting file:" << input_file
         << " -> file:" << encrypted_file << endl;
    ret = encrypt_file(
        ENCRYPT_OPERATION, pw, input_file, encrypted_file);
    if (ret != 0)
    {
        cerr << "Host: processFile(ENCRYPT_OPERATION) failed with " << ret
             << endl;
        exit(-1);
    }

    // Make sure the encryption was doing something. Input and encrypted files
    // are not equal
    cout << "Host: compared file:" << encrypted_file
         << " to file:" << input_file << endl;
    ret = compare_2_files(input_file, encrypted_file);
    if (ret == 0)
    {
        cerr << "Host: checking failed! " << input_file
             << "'s contents are not supposed to be same as " << encrypted_file
             << endl;
        exit(-1);
    }
    cout << "Host: " << input_file << " is NOT equal to " << encrypted_file
         << "as expected" << endl;
    cout << "Host: encryption was done successfully" << endl;


}

void run_decrypt_from_encrypt(const char* encrypted_file, const char* decrypted_file, const char* pw) {
    
    int ret = 0;
    // Decrypt a file
    cout << "Host: decrypting file:" << encrypted_file
         << " to file:" << decrypted_file << endl;

    ret = encrypt_file(
        DECRYPT_OPERATION,
        pw,
        encrypted_file,
        decrypted_file);
    if (ret != 0)
    {
        cerr << "Host: processFile(DECRYPT_OPERATION) failed with " << ret
             << endl;
        exit(-1);
    }
    cout << "Host: compared file: C:/sgxdb-47947ca91d2ea4953089366adf4158ef2af51346/example.seq"
         << " to file:" << decrypted_file << endl;
    ret = compare_2_files("C:/sgxdb-47947ca91d2ea4953089366adf4158ef2af51346/example.seq", decrypted_file);
    if (ret != 0)
    {
        cerr << "Host: checking failed! C:/sgxdb-47947ca91d2ea4953089366adf4158ef2af51346/example.seq "
             << "'s is supposed to be same as " << decrypted_file << endl;
        
    }
    cout << "Host: C:/sgxdb-47947ca91d2ea4953089366adf4158ef2af51346/example.seq" << " is equal to " << decrypted_file << endl;

}

void run_decrypt(const char* encrypted_file, const char* decrypted_file, const char* pw) {

    int ret = 0;
    // Decrypt a file
    cout << "Host: decrypting file:" << encrypted_file
         << " to file:" << decrypted_file << endl;

    ret = decrypt_file_to_enclave(
        DECRYPT_OPERATION,
        pw,
        encrypted_file,
        decrypted_file);
    if (ret != 0)
    {
        cerr << "Host: processFile(DECRYPT_OPERATION) failed with " << ret
             << endl;
        exit(-1);
    }
    cout << "Host: compared file: C:/sgxdb-47947ca91d2ea4953089366adf4158ef2af51346/example.seq"
         << " to file:" << decrypted_file << endl;
    
}

void run_predict(const char* modelfile, const char* seqfile) {
     // Parse arguments and store model-ids-file in enclave's deepbind model
    
    int modelcount = loadmodelids(modelfile);
    model_id_t modelid;
    oe_result_t getidresult;

    loadmodelparams(modelcount);

    // Parse sequences from sequences-file and predict for each in enclave
    predictseqs(seqfile, modelcount);

    cout << "Host: Successfully scored sequences!" << endl;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    int ret = 0;
    
    // const char* encrypted_file = "./out.encrypted";
     
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

    if (check_simulate_opt(&argc, argv))
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    // Check arguments from command line
    cout << "Host: enter main" << endl;
    operation = string(argv[1]);
    
    if (operation.compare("decrypt") == 0 || operation.compare("encrypt") == 0) {
        if (argc != 6) {
            printusage(argv[0]);
        }
    } else if (operation.compare("predict") == 0) {
        if (argc != 5) {
            printusage(argv[0]);
        }
    } else {
        printusage(argv[0]);
    }

    const char* decrypted_file = "./out.decrypted";
    // used for encryption:
    const char* input_file = argv[2]; // example.seq
    const char* output_file = argv[3]; // example.seq.encrypted
    // used for decryption:
    const char* model_file = argv[2]; // example.ids
    const char* encrypted_file = argv[3]; // example.seq.encrypted
    //used for model prediction:
    const char* modelfile = argv[2]; // example.ids
    const char* seqfile = argv[3]; // example.seq

    cout << "Host: create enclave for image:" << argv[4] << endl;
    result = oe_create_fileencryptor_enclave(
        argv[4], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        cerr << "oe_create_fileencryptor_enclave() failed with " << argv[0]
             << " " << result << endl;
        ret = 1;
        goto exit;
    }
    
    if (operation.compare("encrypt") == 0) {
        run_encrypt(input_file, output_file, argv[5]);
        run_decrypt_from_encrypt(output_file, decrypted_file, argv[5]);
        return 0;
    }

    if (operation.compare("decrypt") == 0) {
        int modelcount = loadmodelids(model_file);
        loadmodelparams(modelcount);
        run_decrypt(encrypted_file, decrypted_file, argv[5]);
        return 0;
    }

    if (operation.compare("predict") == 0) {
        run_predict(modelfile, seqfile);
        return 0;
    }

exit:
    cout << "Host: terminate the enclave" << endl;
    cout << "Host: Sample completed successfully." << endl;
    oe_terminate_enclave(enclave);
    return ret;
}
