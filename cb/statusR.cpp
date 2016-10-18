
// Find duplicate r, and print r out

#include <util.h>
#include <string.h>
#include <common.h>
#include <errlog.h>
#include <option.h>
#include <callback.h>

typedef GoogMap<Hash64, bool, Hash64Hasher, Hash64Equal >::Map RscriptMap;

struct statusR:public Callback
{
     optparse::OptionParser parser;

     RscriptMap rscriptMap;

     const uint8_t *txStart;
     uint64_t currTXSize;

     uint64_t currTX;
     uint64_t currBlock;
     uint64_t nbAllR;

  uint64_t nbNormalR;
  uint64_t nbShortR;
  uint64_t nbLongR;
  int max_long_offset;
  int max_short_offset;
  uint64_t short_byte_type_count[32];

     statusR()
          {
               parser
                    .usage("")
                    .version("")
                    .description("Get status of R in blockchain")
                    .epilog("")
                    ;
          }

     virtual const char                   *name() const         { return "rstat"; }
     virtual const optparse::OptionParser *optionParser() const { return &parser;  }
     virtual void aliases(
          std::vector<const char*> &v
          ) const {
          v.push_back("rstat");
     }

     virtual int init(
          int argc,
          const char *argv[]
          ) {
          info("Get status of R in blockchain");
          static uint8_t empty[kSHA64ByteSize] = { 0x42 };
          static uint64_t sz = 15 * 1000 * 1000;
          rscriptMap.setEmptyKey(empty);
          rscriptMap.resize(sz);
          nbAllR = 0;

          for (int i=0; i<32; i++ ) {
            short_byte_type_count[i] = 0;
          }
          nbNormalR = 0;
          nbShortR = 0;
          nbLongR = 0;
          max_long_offset = 0;
          max_short_offset = 0;

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
                 nbAllR++;
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
                         unsigned int n_length_r = p[3];
                         unsigned int n_length_s = p[5+n_length_r];
                         const uint8_t *data_r = &p[4];
                         const uint8_t *S = &p[6+n_length_r];

                         int offset = n_length_r - kSHA256ByteSize;
                         if (unlikely(offset > 0)) {
                           if (offset > max_long_offset) {
                             max_long_offset = offset;
                           }
                           nbLongR++;
                         } else if (unlikely(offset < 0)) {
                           short_byte_type_count[-offset] ++;
                           if (-offset > max_short_offset) {
                             max_short_offset = -offset;
                           }
                           nbShortR++;
                         } else {
                           nbNormalR++;
                         }
                    }
                    p += dataSize;
               }
          }
     }

     virtual void wrapup()
          {
               info("Found %ld R. LongR: %ld[%d], ShortR: %ld[%d], NormalR: %ld, Get %ld[%ld]\n",
                    nbAllR,
                    nbLongR, max_long_offset,
                    nbShortR, max_short_offset,
                    nbNormalR,
                    nbLongR + nbShortR + nbNormalR,
                    nbAllR - (nbLongR + nbShortR + nbNormalR)
                    );

               for (int i=0; i<32; i++ ) {
                 if (short_byte_type_count[i])
                   info("%d = %ld \n", i, short_byte_type_count[i]);
               }

          }
};

static statusR statusr;
