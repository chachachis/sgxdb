#include "deepbind.h"

deepbind::deepbind() {}

void deepbind::addModelID(model_id_t modelid) {
    modelids.push_back(modelid);
}

model_id_t deepbind::getModelID(size_t index) {
    return modelids.at(index);
}

void deepbind::addModelParams(deepbind_model_t model) {
    models.push_back(model);
}

deepbind_model_t deepbind::getModel(size_t index) {
    return models.at(index);
}

size_t deepbind::getModelCount() {
    return models.size();
}

/* The base2index table is used to:
   Convert chars 'A','C','G','T'/'U' to integers 0,1,2,3 respectively.
   Convert char 'N' to UNKNOWN_BASE.
   Convert anything else to INVALID_BASE. */

int deepbind::base2index(unsigned char c)
{

    switch(c) {
        case 'a':
        case 'A':
            return 0;

        case 'c':
        case 'C':
            return 1;

        case 'g':
        case 'G':
            return 2;
        
        case 't':
        case 'T':
        case 'u':
        case 'U':
            return 3;

        case 'n':
        case 'N':
            return UNKNOWN_BASE;
        
    }
    return INVALID_BASE;
	
}

/* The base2comp table is used to:
   Convert chars ACGT to their complements TGCA.
   U is converted to A, and A is always converted to T.
   N is converted to N.
*/

void deepbind::init_base2comp_table()
{
	memset(base2comp, '\0', 256);
	base2comp[(unsigned char)'a'] = base2comp[(unsigned char)'A'] = 'T';
	base2comp[(unsigned char)'c'] = base2comp[(unsigned char)'C'] = 'G';
	base2comp[(unsigned char)'g'] = base2comp[(unsigned char)'G'] = 'C';
	base2comp[(unsigned char)'t'] = base2comp[(unsigned char)'T'] = 'A';
	base2comp[(unsigned char)'u'] = base2comp[(unsigned char)'U'] = 'A';
	base2comp[(unsigned char)'n'] = base2comp[(unsigned char)'N'] = 'N';
}


/* Reverse complement a string in-place */
void deepbind::reverse_complement(unsigned char* seq, size_t seqlen)
{
	size_t i, j;
	for (i = 0, j = seqlen - 1; i <= j; ++i, --j) {
		unsigned char ci = (unsigned char)seq[i];
		unsigned char cj = (unsigned char)seq[j];
		seq[i] = (unsigned char) base2comp[cj];
		seq[j] = (unsigned char) base2comp[ci];
	}
}

int deepbind::get_num_hidden1(deepbind_model_t* model) { return model->has_avg_pooling ? model->num_detectors * 2 : model->num_detectors; }
int deepbind::get_num_hidden2(deepbind_model_t* model) { return model->num_hidden ? model->num_hidden : 1; }


/* Returns index a specific detector coefficient */
int deepbind::indexof_detector_coeff(int num_detector, int detector, int pos, int base)
{
	assert(detector >= 0);
	assert(pos >= 0);
	assert(base >= 0 && base < 4);
	return detector + num_detector * (base + 4 * pos);
}


/* Returns index a specific featuremap coefficient */
int deepbind::indexof_featuremap_coeff(int num_detector, int detector, int pos)
{
	assert(detector >= 0);
	assert(pos >= 0);
	return detector + num_detector * pos;
}


float deepbind::apply_model(deepbind_model_t* model, unsigned char* seq, int seq_len)
{
	int n = seq_len;
	int m = model->detector_len;
	int d = model->num_detectors;
	int num_hidden1 = get_num_hidden1(model);
	int num_hidden2 = get_num_hidden2(model);
	int chunk0 = d * (n + m - 1), chunk1 = num_hidden1, chunk2 = num_hidden2;
	float* mem = (float*)malloc(sizeof(float) * ((unsigned long)chunk0 + (unsigned long)chunk1 + (unsigned long)chunk2));
	float* featuremaps = mem;
	float* hidden1 = mem + chunk0;
	float* hidden2 = mem + chunk0 + chunk1;
	float* detectors = model->detectors;
	float* thresholds = model->thresholds;
	float* weights1 = model->weights1;
	float* biases1 = model->biases1;
	float* weights2 = model->weights2;
	float* biases2 = model->biases2;
	float  p;
	int i, j, k;

	/* Convolution, rectification */
	for (k = 0; k < d; ++k) {
		for (i = 0; i < n + m - 1; ++i) {

			/* Convolve */
			float featuremap_ik = 0;
			for (j = 0; j < m; ++j) {
				unsigned char c = ((i - m + 1) + j >= 0 && (i - m + 1) + j < n) ? seq[(i - m + 1) + j] : 'N';
				int index = base2index(c);
				if (index == UNKNOWN_BASE) {
					for (index = 0; index < 4; ++index){
                    	featuremap_ik += .25f * detectors[indexof_detector_coeff(d, k, j, index)];
                    }
				}
				else {
					featuremap_ik += detectors[indexof_detector_coeff(d, k, j, index)];
				}
			}

			/* Shift and rectify */
			featuremap_ik += thresholds[k];
			if (featuremap_ik < 0)
				featuremap_ik = 0;

			featuremaps[indexof_featuremap_coeff(d, k, i)] = featuremap_ik;
		}
	}

	/* Pooling */
	if (model->has_avg_pooling) {
		for (k = 0; k < d; ++k) {
			float z_max = 0;
			float z_sum = 0;
			for (i = 0; i < n + m - 1; ++i) {
				float featuremap_ik = featuremaps[indexof_featuremap_coeff(d, k, i)];
				z_sum += featuremap_ik;
				if (z_max < featuremap_ik)
					z_max = featuremap_ik;
			}
			hidden1[2 * k + 0] = z_max;
			hidden1[2 * k + 1] = z_sum / (float)(n + m - 1);
		}
	}
	else {
		for (k = 0; k < d; ++k) {
			float z_max = 0;
			for (i = 0; i < n + m - 1; ++i) {
				float featuremap_ik = featuremaps[indexof_featuremap_coeff(d, k, i)];
				if (z_max < featuremap_ik)
					z_max = featuremap_ik;
			}
			hidden1[k] = z_max;
		}
	}

	/* First hidden layer after convolution and pooling */
	for (j = 0; j < num_hidden2; ++j) {
		float h_j = biases1[j];
		for (i = 0; i < num_hidden1; ++i) {
			h_j += weights1[i * num_hidden2 + j] * hidden1[i];
		}
		hidden2[j] = h_j;
	}

	if (num_hidden2 == 1) {
		/* No second hidden layer, so the lone hidden value is the final score */
		p = hidden2[0];
	}
	else {
		/* Second hidden layer, has its own biases, rectification, and weights */
		p = biases2[0];
		for (j = 0; j < num_hidden2; ++j) {
			float h_j = hidden2[j];
			if (h_j < 0)
				h_j = 0;
			p += weights2[j] * h_j;
		}
	}

	free(mem);
	return p;
}

float deepbind::predict_seq(size_t modelindex, 
                        unsigned char* seq, 
                        size_t seqlen,
                        size_t window_size,
                        int average_flag) {

    deepbind_model_t model = getModel(modelindex);

    float scan_score = average_flag ? 0.0f : -10000.0f;
	int i;
	if (window_size < 1)
		window_size = (size_t)(model.detector_len * 1.5);
	if (seqlen <= window_size)
		return apply_model(&model, seq, (int)seqlen);
	for (i = 0; i < (int)seqlen - (int)window_size + 1; i++) {
		float score_i = apply_model(&model, seq + i, (int) window_size);
		if (average_flag)
			scan_score += score_i;
		else if (score_i > scan_score)
			scan_score = score_i;
	}
	if (average_flag)
		scan_score /= seqlen;
	return scan_score;
}

float deepbind::scan_model(size_t modelindex, 
                            unsigned char* seq, 
                            size_t seqlen,
                            size_t window_size,
                            int average_flag) {
    float score = predict_seq(modelindex, seq, seqlen, window_size, average_flag);

    deepbind_model_t model = getModel(modelindex);
    if (model.reverse_complement) {
        // Reverse complement also needs to be scored. Take the max. 
        float rscore;
        reverse_complement(seq, seqlen);
        rscore = predict_seq(modelindex, seq, seqlen, window_size, average_flag);
        if (rscore > score)
            score = rscore;
    }
    return score;
}