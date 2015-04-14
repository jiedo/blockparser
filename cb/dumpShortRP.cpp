
// get uniq r:
// ./parse shortr > results
// $ cat results | awk '{print $1}' | sort | uniq > rscript.data

#include <util.h>
#include <string.h>
#include <common.h>
#include <errlog.h>
#include <option.h>
#include <callback.h>

typedef GoogMap<Hash64, bool, Hash64Hasher, Hash64Equal >::Map RscriptMap;

struct DumpShortRP:public Callback
{
     optparse::OptionParser parser;

     RscriptMap rscriptMap;
     const uint8_t *txStart;
     uint64_t currTXSize;

     uint64_t currTX;
     uint64_t currBlock;
     uint64_t bTime;
     uint64_t nbBadR;
     uint64_t nbBadP;

     DumpShortRP()
          {
               parser
                    .usage("")
                    .version("")
                    .description("find all dumpshortrp blocks in the blockchain")
                    .epilog("")
                    ;
          }

     virtual const char                   *name() const         { return "rpshort"; }
     virtual const optparse::OptionParser *optionParser() const { return &parser;    }
     // virtual bool                         needTXHash() const    { return true;       }
     virtual void aliases(
          std::vector<const char*> &v
          ) const {
          v.push_back("rpshort");
     }

     virtual int init(
          int argc,
          const char *argv[]
          ) {
          info("Finding all dumpshortrp blocks in blockchain");
          static uint8_t empty[kSHA64ByteSize] = { 0x42 };
          static uint64_t sz = 15 * 1000 * 1000;
          rscriptMap.setEmptyKey(empty);
          rscriptMap.resize(sz);

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
                        uint8_t *publickeyx = allocHash64();
                        memcpy(publickeyx, p+1, kSHA64ByteSize);

                        auto i = rscriptMap.find(publickeyx);
                        if(likely(rscriptMap.end()==i)) {
                          showHex(publickeyx, 8, false);
                          printf(" P\n");
                          nbBadP++;
                          fflush(stdout);
                          rscriptMap[publickeyx] = true;
                        }else{
                          freeHash64(publickeyx);
                        }
                      }

                    int iscanonicalsignature = IsCanonicalSignature(p, dataSize);
                    if (iscanonicalsignature == 0) // ok
                    {
                         unsigned int nLenR = p[3];
                         unsigned int nLenS = p[5+nLenR];
                         const uint8_t *R = &p[4];
                         const uint8_t *S = &p[6+nLenR];

                         uint8_t *rscript = allocHash64();
                         if (unlikely(nLenR > kSHA256ByteSize)) {
                           memcpy(rscript, &(R[nLenR-kSHA256ByteSize]), kSHA64ByteSize);
                         }
                         else if (unlikely(nLenR < kSHA256ByteSize)) {
                           unsigned int offset = kSHA256ByteSize - nLenR;
                           if (kSHA64ByteSize > offset) {
                             memset(rscript, 0, offset);
                             memcpy(rscript + offset, R, kSHA64ByteSize-offset);
                           }else{
                             memset(rscript, 0, kSHA64ByteSize);
                           }
                         }
                         else {
                           memcpy(rscript, R, kSHA64ByteSize);
                         }

                         auto i = rscriptMap.find(rscript);
                         if(likely(rscriptMap.end()==i)) {
                           showHex(rscript, 8, false);
                           printf(" R\n");
                           nbBadR++;
                           fflush(stdout);
                           rscriptMap[rscript] = true;
                         }else{
                           freeHash64(rscript);
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

static DumpShortRP dumpshortrp;
