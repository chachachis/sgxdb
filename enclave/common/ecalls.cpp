// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include "encryptor.h"
#include "fileencryptor_t.h"
#include "shared.h"
#include <vector>

// Declare a static dispatcher object for enabling for better organization
// of enclave-wise global variables
static ecall_dispatcher dispatcher;

#include "deepbind.h"
static deepbind dbmodel;

int initialize_encryptor(
    bool encrypt,
    const char* password,
    size_t password_len,
    encryption_header_t* header)
{
    return dispatcher.initialize(encrypt, password, password_len, header);
}

int encrypt_block(
    bool encrypt,
    unsigned char* input_buf,
    unsigned char* output_buf,
    size_t size)
{
    return dispatcher.encrypt_block(encrypt, input_buf, output_buf, size);
}

void close_encryptor()
{
    return dispatcher.close();
}

/* DEFINITION OF ECALLS */

size_t ecall_checkvalidseq(char* seq, size_t seqlen) {
	size_t i;
	if (seqlen == 0) {
		// return false;
    }
	for (i = 0; i < seqlen; ++i) {
		char base = seq[i];
		if (dbmodel.base2index(base) == INVALID_BASE) {
			return i;
		}
	}
	return 0;
}

void ecall_addIDtomodel(int major, int minor) {
    model_id_t id = {major, minor};
    dbmodel.addModelID(id);
}

model_id_t ecall_getdbmodelid(size_t index) {
    model_id_t modelid;
	modelid.major = dbmodel.getModelID(index).major;
    modelid.minor = dbmodel.getModelID(index).minor;
	return modelid;
}

void ecall_loadparams(deepbind_model_t model) {
    dbmodel.addModelParams(model);
}

void ecall_initmodel() {
	dbmodel.init_base2comp_table();
}

float ecall_scanmodel(size_t modelindex, 
						char* seq, 
						size_t seqlen,
						size_t window_size,
						int average_flag) {
    
	return dbmodel.scan_model(modelindex, seq, seqlen, window_size, average_flag);
}