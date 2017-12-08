
// print tx detail about specific r
// need:
//     rscript.data
//     publickeyx.data

// ./parse rscript > results
//

#include <util.h>
#include <string.h>
#include <common.h>
#include <errlog.h>
#include <option.h>
#include <callback.h>

typedef GoogMap<Hash256, bool, Hash256Hasher, Hash256Equal >::Map ScriptMap;


int load_hash_data(const char*name, ScriptMap &gMap){
  FILE* fp_in = fopen(name, "r");
  size_t getline_n = 256;
  char *getline_buf = (char *)malloc(getline_n);

  int n_loaded = 0;
  while(1) {
    // Read the value.
    size_t size = getline(&getline_buf, &getline_n, fp_in);
    if ((int)size < 0){
      break;
    }
    size += -3;                 // remove \n, ' ', and  TAG
    getline_buf[size] = 0;

    uint8_t * hash256 = allocHash256();
    memset(hash256, 0, kSHA256ByteSize);
    fromHex(hash256, (const uint8_t *)getline_buf, size, false, false);
    gMap[hash256] = true;
    n_loaded ++;
  }
  fclose(fp_in);

  free(getline_buf);
  info("%d loaded from %s.", n_loaded, name);
  return n_loaded;
}

struct DumpRscript:public Callback
{
     optparse::OptionParser parser;

     ScriptMap gRscriptMap;
     ScriptMap gPublicKeyXMap;

     const uint8_t *txStart;
     uint64_t currTXSize;

     uint64_t currTX;
     uint64_t bTime;
     uint64_t nbBadR;
     uint64_t nbBadP;
  bool is_currTX_dumped = false;

     DumpRscript()
          {
               parser
                    .usage("")
                    .version("")
                    .description("find all dumprscript blocks in the blockchain")
                    .epilog("")
                    ;
          }

     virtual const char                   *name() const         { return "rscript"; }
     virtual const optparse::OptionParser *optionParser() const { return &parser;   }
     virtual bool                         needTXHash() const    { return true;     }
     virtual void aliases(
          std::vector<const char*> &v
          ) const {
          v.push_back("rscript");
     }

     virtual int init(
          int argc,
          const char *argv[]
          ) {
          info("Finding all dumprscript blocks in blockchain");
          static uint8_t empty[kSHA256ByteSize] = { 0x42 };
          static uint64_t sz = 15 * 1000;
          gRscriptMap.setEmptyKey(empty);
          load_hash_data("rscript.data", gRscriptMap);
          gRscriptMap.resize(sz);

          gPublicKeyXMap.setEmptyKey(empty);
          load_hash_data("publickeyx.data", gPublicKeyXMap);
          gPublicKeyXMap.resize(sz);
          nbBadP = 0;
          nbBadR = 0;
          return 0;
     }


     virtual void startBlock(
          const Block *b,
          uint64_t chainSize
          ) {
          const uint8_t *p = b->chunk->getData();
          SKIP(uint32_t, version, p);
          SKIP(uint256_t, prevBlkHash, p);
          SKIP(uint256_t, blkMerkleRoot, p);
          LOAD(uint32_t, blkTime, p);

          bTime = blkTime;
          currTX = 0;
     }

     virtual void startTX(
          const uint8_t *p,
          const uint8_t *hash,
          const uint8_t *txEnd
          ) {
          txStart = p;
          currTXSize = txEnd - txStart;
          currTX++;
          is_currTX_dumped = false;
     }

    virtual void edge(
        uint64_t      value,
        const uint8_t *upTXHash,
        uint64_t      outputIndex,
        const uint8_t *outputScript,
        uint64_t      outputScriptSize,
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
                        auto i = gPublicKeyXMap.find(&p[1]);
                        if(unlikely(gPublicKeyXMap.end()!=i)) {
                          showHex(outputScript, outputScriptSize, false);
                          printf(" P %ld %ld %ld ",
                                 outputIndex,
                                 inputIndex,
                                 bTime
                                 );
                          if (!is_currTX_dumped) {
                            showHex(txStart, currTXSize, false);
                            is_currTX_dumped = true;
                          }
                          printf("\n");
                          nbBadP++;
                          fflush(stdout);
                        }
                      }

                    int iscanonicalsignature = IsCanonicalSignature(p, dataSize);
                    if (iscanonicalsignature == 0) // ok
                    {
                         unsigned int nLenR = p[3];
                         unsigned int nLenS = p[5+nLenR];
                         const uint8_t *R = &p[4];
                         const uint8_t *S = &p[6+nLenR];

                         const uint8_t *rscript;
                         uint256_t rscript_h256;
                         if (unlikely(nLenR > kSHA256ByteSize)) {
                           rscript = &(R[nLenR-kSHA256ByteSize]);
                           //memcpy(rscript, &(R[nLenR-kSHA256ByteSize]), kSHA256ByteSize);
                         }
                         else {
                              memset(rscript_h256.v, 0, kSHA256ByteSize);
                              memcpy(rscript_h256.v, R, nLenR);
                              rscript = (const uint8_t *)(&(rscript_h256.v));
                         }
                         auto i = gRscriptMap.find(rscript);
                         if(unlikely(gRscriptMap.end()!=i)) {
                           showHex(outputScript, outputScriptSize, false);
                              printf(" R %ld %ld %ld ",
                                     outputIndex,
                                     inputIndex,
                                     bTime
                                   );
                              if (!is_currTX_dumped) {
                                showHex(txStart, currTXSize, false);
                                is_currTX_dumped = true;
                              }
                              printf("\n");
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
            info("Found %ld dup R. %ld Bad R(by public key used)\n", nbBadR, nbBadP);
          }
};

static DumpRscript dumprscript;
