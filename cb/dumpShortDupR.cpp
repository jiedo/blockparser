
// Find duplicate r, and print r out

#include <util.h>
#include <string.h>
#include <common.h>
#include <errlog.h>
#include <option.h>
#include <callback.h>

typedef GoogMap<Hash64, bool, Hash64Hasher, Hash64Equal >::Map RscriptMap;

struct dumpShortDupR:public Callback
{
     optparse::OptionParser parser;

     RscriptMap rscriptMap;

     const uint8_t *txStart;
     uint64_t currTXSize;

     uint64_t currTX;
     uint64_t currBlock;
     uint64_t nbBadR;

     dumpShortDupR()
          {
               parser
                    .usage("")
                    .version("")
                    .description("find all dumpshortdupr blocks in the blockchain")
                    .epilog("")
                    ;
          }

     virtual const char                   *name() const         { return "dupr"; }
     virtual const optparse::OptionParser *optionParser() const { return &parser;  }
     virtual void aliases(
          std::vector<const char*> &v
          ) const {
          v.push_back("dupr");
     }

     virtual int init(
          int argc,
          const char *argv[]
          ) {
          info("Finding all dumpshortdupr blocks in blockchain");
          static uint8_t empty[kSHA64ByteSize] = { 0x42 };
          static uint64_t sz = 15 * 1000 * 1000;
          rscriptMap.setEmptyKey(empty);
          rscriptMap.resize(sz);
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

                    int iscanonicalsignature = IsCanonicalSignature(p, dataSize);
                    if (iscanonicalsignature == 0) // ok
                    {
                         unsigned int nLenR = p[3];
                         unsigned int nLenS = p[5+nLenR];
                         const uint8_t *R = &p[4];
                         const uint8_t *S = &p[6+nLenR];

                         uint8_t *rscript = allocHash64();
                         if (unlikely(nLenR > kSHA256ByteSize))
                              memcpy(rscript, &(R[nLenR-kSHA256ByteSize]), kSHA64ByteSize);
                         else
                              memcpy(rscript, R, kSHA64ByteSize);

                         auto i = rscriptMap.find(rscript);
                         if(unlikely(rscriptMap.end()!=i)) {
                              freeHash64(rscript);
                              // lenR R outscript outi ini transection [origin transection]
                              if (unlikely(nLenR > kSHA256ByteSize))
                                showHex(&(R[nLenR-kSHA256ByteSize]), kSHA256ByteSize, false);
                              else
                                showHex(R, nLenR, false);
                              printf("\tblock:%" PRIu64 "\ttx:%" PRIu64 "\n",
                                     currBlock, currTX);

                              fflush(stdout);
                              nbBadR++;
                         }
                         else {
                              rscriptMap[rscript] = true;
                         }
                    }
                    p += dataSize;
               }
          }
     }

     virtual void wrapup()
          {
               info("Found %" PRIu64 " dup R.\n", nbBadR);
          }
};

static dumpShortDupR dumpshortdupr;
