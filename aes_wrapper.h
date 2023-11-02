#ifndef _ASE_WRAPPER_H_
#define _ASE_WRAPPER_H_

#ifndef WITH_OPENSSL_LIB

#include <stdint.h>

# define AES_ENCRYPT     1
# define AES_DECRYPT     0

# define AES_MAXNR 14

typedef uint32_t u32;
typedef uint64_t u64;

struct aes_key_st {
# ifdef AES_LONG
    unsigned long rd_key[4 * (AES_MAXNR + 1)];
# else
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
# endif
    int rounds;
};
typedef struct aes_key_st AES_KEY;

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
                     const AES_KEY *key, const int enc);
#endif

#endif