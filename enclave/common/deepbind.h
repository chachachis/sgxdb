#include <vector>
#include "shared.h"

#define INVALID_BASE -1
#define UNKNOWN_BASE 4

using namespace std;

class deepbind {

    private:
    vector<model_id_t> modelids;
    vector<deepbind_model_t> models;
    char base2comp[256];


    void reverse_complement(unsigned char* seq, size_t seqlen);
    int get_num_hidden1(deepbind_model_t* model);
    int get_num_hidden2(deepbind_model_t* model);
    int indexof_detector_coeff(int num_detector, int detector, int pos, int base);
    int indexof_featuremap_coeff(int num_detector, int detector, int pos);
    float apply_model(deepbind_model_t* model, unsigned char* seq, int seq_len);
    float predict_seq(size_t modelindex, 
                        unsigned char* seq, 
                        size_t seqlen,
                        size_t window_size,
                        int average_flag);

    public:
    deepbind();
    void addModelID(model_id_t modelid);
    model_id_t getModelID(size_t index);
    void addModelParams(deepbind_model_t model);
    int base2index(unsigned char c);
    deepbind_model_t getModel(size_t index);
    size_t getModelCount();

    void init_base2comp_table();
    float scan_model(size_t modelindex, 
                            unsigned char* seq, 
                            size_t seqlen,
                            size_t window_size,
                            int average_flag);                 

};