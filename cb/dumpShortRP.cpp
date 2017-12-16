// Find duplicate r, and find bad r(by public key used). then print it out

#include <util.h>
#include <string.h>
#include <common.h>
#include <errlog.h>
#include <option.h>
#include <callback.h>

#include "bloom.h"

typedef GoogMap<Hash64, bool, Hash64Hasher, Hash64Equal >::Map RscriptMap;

struct DumpShortRP:public Callback
{
     optparse::OptionParser parser;

  struct bloom bloom_rscript;
  struct bloom bloom_publickey;

     // RscriptMap gRscriptMap;
     // RscriptMap gPublicKeyMap;

     const uint8_t *txStart;

     uint64_t currTX;
     uint64_t nbBadR;
     uint64_t nbBadP_aleady_in_R;
     uint64_t nbBadR_aleady_in_P;

     DumpShortRP()
          {
               parser
                    .usage("")
                    .version("")
                    .description("find all dumpshortrp blocks in the blockchain")
                    .epilog("")
                    ;
          }

     virtual const char                   *name() const         { return "rpq"; }
     virtual const optparse::OptionParser *optionParser() const { return &parser;    }
     virtual void aliases(
          std::vector<const char*> &v
          ) const {
          v.push_back("rpq");
     }

     virtual int init(
          int argc,
          const char *argv[]
          ) {

       const unsigned long int num_bloom = 2800000000L;
       int is_ok_rscript = bloom_init(&bloom_rscript,     num_bloom, 0.00002);
       int is_ok_publickey = bloom_init(&bloom_publickey, num_bloom, 0.00002);

       info("init bloom filter rscript[%ld]=%d, bloom filter publickey[%ld]=%d.\n",
            bloom_rscript.bytes, is_ok_rscript, bloom_publickey.bytes, is_ok_publickey);

          // static uint8_t empty[kSHA64ByteSize] = { 0x42 };
          // static uint64_t sz = 15 * 1000 * 1000;
          // gRscriptMap.setEmptyKey(empty);
          // gRscriptMap.resize(sz);

          // gPublicKeyMap.setEmptyKey(empty);
          // gPublicKeyMap.resize(sz);

          nbBadR = 0;
          nbBadP_aleady_in_R = 0;
          nbBadR_aleady_in_P = 0;
          return 0;
     }

    virtual void startBlock(const Block *b, uint64_t chainSize) {
          const uint8_t *p = b->chunk->getData();
          SKIP(uint32_t, version, p);
          SKIP(uint256_t, prevBlkHash, p);
          SKIP(uint256_t, blkMerkleRoot, p);
          LOAD(uint32_t, blkTime, p);

          currTX = 0;
     }

     virtual void startTX(
          const uint8_t *p,
          const uint8_t *hash,
          const uint8_t *txEnd
          ) {
          txStart = p;
          currTX++;
     }

     virtual void endInput(
                        const uint8_t *pend,
                        const uint8_t *upTXHash,
                        uint64_t      outputIndex,
                        const uint8_t *downTXHash,
                        uint64_t      inputIndex,
                        const uint8_t *inputScript,
                        uint64_t      inputScriptSize
                        ) {
          const uint8_t *p = inputScript;
          const uint8_t *e = p + (size_t)inputScriptSize;

          while(likely(p<e)) {
               LOAD(uint8_t, c, p);
               bool isImmediate = (0<c && c<0x4f);
               if(isImmediate) {
                    uint64_t dataSize = 0;
                         if(likely(0x4b>=c)) {                       dataSize = c; }
                    else if(likely(0x4c==c)) { LOAD( uint8_t, v, p); dataSize = v; } // 76
                    else if(likely(0x4d==c)) { LOAD(uint16_t, v, p); dataSize = v; }
                    else if(likely(0x4e==c)) { LOAD(uint32_t, v, p); dataSize = v; }

                    if (p >= e) break;
                    if (p+dataSize >= e)
                         dataSize = e-p;

                    int iscanonicalpubkey = IsCanonicalPubKey(p, dataSize);
                    if (iscanonicalpubkey == 0) // ok
                      {

                        const uint8_t *publickeyx = p+1;
                        if (unlikely(bloom_check(&bloom_rscript, (void*)publickeyx, kSHA256ByteSize))) {
                          showHex(publickeyx, kSHA256ByteSize, false);
                          printf(" P\n");
                          nbBadP_aleady_in_R++;
                          fflush(stdout);
                        }
                        bloom_add(&bloom_publickey, (void*)publickeyx, kSHA256ByteSize);

                      }

                    int iscanonicalsignature = IsCanonicalSignature(p, dataSize);
                    if (iscanonicalsignature == 0) // ok
                    {
                      unsigned int n_length_r = p[3];
                      unsigned int n_length_s = p[5+n_length_r];
                      const uint8_t *data_r = &p[4];
                      const uint8_t *S = &p[6+n_length_r];

                      const uint8_t *rscript = data_r;

                      int offset = n_length_r - kSHA256ByteSize;
                      if (unlikely(offset > 0)) {
                        rscript =  &(data_r[offset]);
                        offset = 0;
                      }
                      offset += kSHA256ByteSize;

                      if (unlikely(bloom_check(&bloom_publickey, (void*)rscript, offset))) {
                        showHex(rscript, offset, false);
                        printf(" Q\n");
                        nbBadR_aleady_in_P++;
                        fflush(stdout);
                      }

                      if (unlikely(bloom_add(&bloom_rscript, (void*)rscript, offset))) {
                        showHex(rscript, offset, false);
                        printf(" R\n");
                        nbBadR++;
                        fflush(stdout);
                      }
                    }
                    p += dataSize;
               }
          }
     }

     virtual void wrapup()
          {
            info("Found %ld dup R. %ld Bad R(leak by Public key use).  %ld Bad R(Public key aready used).\n",
                 nbBadR, nbBadP_aleady_in_R, nbBadR_aleady_in_P);
          }
};

static DumpShortRP dumpshortrp;
