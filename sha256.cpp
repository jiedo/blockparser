
#include <sha256.h>
#include "openssl/sha.h"

void sha256(
    uint8_t       *result,
    const uint8_t *data,
    size_t        len
)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(result, &sha256);
}


void sha256_wit(
    uint8_t       *result,
    const uint8_t *data,
    size_t        len_io,
    size_t        len_wit
)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, 4);                    // version
    SHA256_Update(&sha256, data+4+2, len_io);           // inputs/outputs
    SHA256_Update(&sha256, data+4+2+len_io+len_wit, 4); // locktime
    SHA256_Final(result, &sha256);
}
