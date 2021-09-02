// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include "encryptor.h"
#include "fileencryptor_t.h"
#include "shared.h"
#include "common/trace.h"
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

size_t ecall_checkvalidseq(unsigned char* seq, size_t seqlen) {
	size_t i;
	if (seqlen == 0) {
		// return false;
    }
	for (i = 0; i < seqlen; ++i) {
		unsigned char base = seq[i];
		if (dbmodel.base2index(base) == INVALID_BASE) {
			return i;
		}
	}
	// TRACE_ENCLAVE("valid sequence");
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
						unsigned char* seq, 
						size_t seqlen,
						size_t window_size,
						int average_flag) {
    
	return dbmodel.scan_model(modelindex, seq, seqlen, window_size, average_flag);
}

int ecall_decryptpredict(unsigned char* inbuff, size_t size, bool eof, size_t paddingsize) {
    unsigned char outbuff[MAX_SEQ_SIZE];
	dispatcher.encrypt_block(false, inbuff, outbuff, size);
	
	if (eof)
	{
		size = paddingsize;
		// TRACE_ENCLAVE("bytes to write = %i", size);
		
	}

	// TRACE_ENCLAVE("outbuff is: \n%s", outbuff);
    // parse decrypted outbuff, predict a score for each model
    size_t bytesused = 0;
    size_t seqstart = 0;
	size_t seqlen = 0;
	// int sequencecount = 0;
	bool seqdetected = false;

    while (bytesused < size) {
		// TRACE_ENCLAVE("outbuff[bytesused] = %c", outbuff[bytesused]);
        if (outbuff[bytesused] != '\n') {
            if (outbuff[bytesused] == ' ' || outbuff[bytesused] == '\t' || outbuff[bytesused] == '\r') {
                // whitespace - ignore
                bytesused++;
            } else {
                // not whitespace, add to seq
                seqlen++;
                bytesused++;
				seqdetected = true;
            }
        } else {
            // New line indicates sequence is complete. Predict and print scores
            // Check valid sequence
			// TRACE_ENCLAVE("predicting sequence %i", ++sequencecount);
            if (ecall_checkvalidseq(outbuff+seqstart, seqlen) != 0) {
                return -1;
            }

            // Predict and print scores
            size_t modelcount = dbmodel.getModelCount();
			// TRACE_ENCLAVE("modelcount = %i", modelcount);
            float score;
            vector<float> scores;
			// TRACE_ENCLAVE("seq = %s", outbuff+seqstart);
			// TRACE_ENCLAVE("seqlen = %i", seqlen);
            for (size_t i = 0; i < modelcount; i++) {
                score = ecall_scanmodel(i, outbuff+seqstart, seqlen, 0, 0);
                scores.push_back(score);
				// TRACE_ENCLAVE("score %f", score);
            }
            float* scoresarray = &scores[0];
            oe_result_t result;
            result = hcall_printscores(scoresarray, modelcount);
            if (result != OE_OK) {
                return -2;
            }
            bytesused++;
            seqstart = bytesused;
			seqlen = 0;
			seqdetected = false;
        }
    }
    if (eof && seqdetected) {
        // score remaining sequence, print and return
        // Predict and print scores
		// TRACE_ENCLAVE("eof true, predict rest of scores");
		// TRACE_ENCLAVE("seq = %s", outbuff+seqstart);
		// TRACE_ENCLAVE("seqstart, size = %i, %i", seqstart, size);
        size_t modelcount = dbmodel.getModelCount();
        float score;
        vector<float> scores;
        for (size_t i = 0; i < modelcount; i++) {
            score = ecall_scanmodel(i, outbuff+seqstart, seqlen, 0, 0);
            scores.push_back(score);
			// TRACE_ENCLAVE("score %f", score);
        }
        float* scoresarray = &scores[0];
        oe_result_t result;
        result = hcall_printscores(scoresarray, modelcount);
        if (result != OE_OK) {
            return -2;
        }
        return 0;
        
    }
    // return number of bytes unused given not end of encrypted file
    return (int)seqlen;
	// return 0;
	
}
