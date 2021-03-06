#ifndef __SHA256_H__
    #define __SHA256_H__

    #include <stddef.h>
    #include <inttypes.h>
    enum { kSHA256ByteSize = 32 };
    void sha256(
        uint8_t       *result,
        const uint8_t *data,
        size_t        len
    );
    void sha256_wit(
        uint8_t       *result,
        const uint8_t *data,
        size_t        len_io,
        size_t        len_wit
    );

#endif // __SHA256_H__
