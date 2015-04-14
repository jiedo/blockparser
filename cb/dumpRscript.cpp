
// get uniq r:
// ./parse shortr > results
// $ cat results | awk '{print $1}' | sort | uniq > rscript.data

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
    getline_buf[size-1] = 0;

    uint8_t * hash256 = allocHash256();
    memset(hash256, 0, kSHA256ByteSize);
    fromHex(hash256, (const uint8_t *)getline_buf, kSHA256ByteSize, false, false);
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
     ScriptMap gPublicKeyMap;

     const uint8_t *txStart;
     uint64_t currTXSize;

     uint64_t currTX;
     uint64_t currBlock;
     uint64_t bTime;
     uint64_t nbBadR;
     uint64_t nbBadP;

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
     virtual const optparse::OptionParser *optionParser() const { return &parser;    }
     virtual bool                         needTXHash() const    { return true;       }
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

          gPublicKeyMap.setEmptyKey(empty);
          load_hash_data("publickey.data", gPublicKeyMap);
          gPublicKeyMap.resize(sz);
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
          currBlock = b->height;
          currTX = 0;

        static double startTime = 0;
        static double lastStatTime = 0;
        static uint64_t offset = 0;

        offset += b->chunk->getSize();
        double now = usecs();
        double elapsed = now - lastStatTime;
        bool longEnough = (5*1000*1000<elapsed);
        bool closeEnough = ((chainSize - offset)<80);
        if(unlikely(longEnough || closeEnough)) {
            if(0==startTime) {
                startTime = now;
            }

            double progress = offset/(double)chainSize;
            double elasedSinceStart = 1e-6*(now - startTime);
            double speed = progress / elasedSinceStart;
            info(
                "%8" PRIu64 " blocks, "
                "%6.2f%% , "
                "elapsed = %5.2fs , "
                "eta = %5.2fs"
                ,
                currBlock,
                100.0*progress,
                elasedSinceStart,
                (1.0/speed) - elasedSinceStart
            );

            lastStatTime = now;
        }

     }

     virtual void startTX(
          const uint8_t *p,
          const uint8_t *hash,
          const uint8_t *txEnd
          ) {
          txStart = p;
          currTXSize = txEnd - txStart;
          currTX++;
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
                        auto i = gPublicKeyMap.find(&p[1]);
                        if(unlikely(gPublicKeyMap.end()!=i)) {
                          showHex(outputScript, outputScriptSize, false);
                          printf(" P %" PRIu64 " %" PRIu64 " %" PRIu64 " ",
                                 outputIndex,
                                 inputIndex,
                                 bTime
                                 );
                          showHex(txStart, currTXSize, false);
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
                              printf(" R %" PRIu64 " %" PRIu64 " %" PRIu64 " ",
                                     outputIndex,
                                     inputIndex,
                                     bTime
                                   );
                              showHex(txStart, currTXSize, false);
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
            info("Found %" PRIu64 " dup R. %" PRIu64 " Bad R(by public key used)\n", nbBadR, nbBadP);
          }
};

static DumpRscript dumprscript;
