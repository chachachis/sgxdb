# Secure Analysis of Genetic Data using Intel SGX
Submitted by Christina Chin in partial fulfillment of the requirements for the MSc Degree in Computing Science of Imperial College, September 2021.

## System Requirements
A x86-64 machine with system support for SGX1 is required. Note that SGX must be both supported and enabled from the system BIOS settings. Detailed instructions can be found in the [Open Enclave documentation](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Windows.md). This repository was built using the the Microsoft C++ (MSVC) C and C++ compilers downloaded using Microsoft Visual Studio Build Tools 2019. Using other C++ compilers may lead to compiler errors.

The latest installation of CMake is also required to build this project.

Instructions to set up the Open Enclave SDK are provided in the GitHub repository under docs - GettingStartedDocs.
[https://github.com/openenclave/openenclave](https://github.com/openenclave/openenclave)

## Running an Enclave Application

For each terminal session, set OE config file path using the following command.
```c
set CMAKE_PREFIX_PATH=%CMAKE_PREFIX_PATH%;C:\openenclave\lib\openenclave\cmake
```

To run, call any of the custom ninja commands (encrypt, decrypt, predict) to run the executable on example input files.
```c
mkdir build
cd build
cmake .. -G Ninja -DNUGET_PACKAGE_PATH=C:\oe_prereqs
ninja (command)
```

Alternatively, specify your own command line inputs using the following format:
```c
host/file-encryptor_host.exe encrypt input-file dest-file enclave-image-path password
host/file-encryptor_host.exe decrypt ids-file encrypted-seq-file enclave-image-path password
host/file-encryptor_host.exe predict ids-file seq-file enclave-image-path
```

## Acknowledgements
This project includes elements of the [DeepBind neural network models](http://tools.genes.toronto.edu/deepbind/) and [Open Enclave SDK](https://github.com/openenclave/openenclave), particularly samples provided on the use of enclave calls and file encryption.

