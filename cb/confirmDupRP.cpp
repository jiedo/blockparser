
// print tx detail about specific r
// need:
//     rscript.data
//     publickey.data

// ./parse rscript > results
//

#include <util.h>
#include <string.h>
#include <common.h>
#include <errlog.h>
#include <option.h>
#include <callback.h>

typedef GoogMap<Hash256, int, Hash256Hasher, Hash256Equal >::Map ScriptMap;


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
    gMap[hash256] = 0;
    n_loaded ++;
  }
  fclose(fp_in);

  free(getline_buf);
  info("%d loaded from %s.", n_loaded, name);
  return n_loaded;
}

struct ConfirmDupRP:public Callback
{
     optparse::OptionParser parser;

     ScriptMap gRMap;
     ScriptMap gQMap;
     ScriptMap gPublicKeyXMap;

     const uint8_t *txStart;
     uint64_t currTXSize;

     uint64_t currTX;
     uint64_t currBlock;
     uint64_t bTime;
     uint64_t nbBadR;
     uint64_t nbBadP_aleady_in_R;
     uint64_t nbBadR_aleady_in_P;

     ConfirmDupRP()
          {
               parser
                    .usage("")
                    .version("")
                    .description("find all confirmDupRP blocks in the blockchain")
                    .epilog("")
                    ;
          }

     virtual const char                   *name() const         { return "confirmrp"; }
     virtual const optparse::OptionParser *optionParser() const { return &parser;    }
     virtual bool                         needTXHash() const    { return true;       }
     virtual void aliases(
          std::vector<const char*> &v
          ) const {
          v.push_back("confirmrp");
     }

     virtual int init(
          int argc,
          const char *argv[]
          ) {
          info("Finding all confirmDupRP blocks in blockchain");
          static uint8_t empty[kSHA256ByteSize] = { 0x42 };
          static uint64_t sz = 1000;
          gRMap.setEmptyKey(empty);
          load_hash_data("r.data", gRMap);
          gRMap.resize(sz);

          gQMap.setEmptyKey(empty);
          load_hash_data("q.data", gQMap);
          gQMap.resize(sz);

          gPublicKeyXMap.setEmptyKey(empty);
          load_hash_data("p.data", gPublicKeyXMap);
          gPublicKeyXMap.resize(sz);

          nbBadR = 0;
          nbBadP_aleady_in_R = 0;
          nbBadR_aleady_in_P = 0;
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
                "%8ld blocks, "
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
                        auto i = gQMap.find(&p[1]);
                        if(unlikely(gQMap.end()!=i)) {
                           showHex(&p[1], kSHA256ByteSize, false);
                           printf(" Q\n");
                           nbBadR_aleady_in_P++;
                           fflush(stdout);
                         }
                      }

                    int iscanonicalsignature = IsCanonicalSignature(p, dataSize);
                    if (iscanonicalsignature == 0) // ok
                    {
                      unsigned int n_length_r = p[3];
                      unsigned int n_length_s = p[5+n_length_r];
                      const uint8_t *data_r = &p[4];
                      const uint8_t *S = &p[6+n_length_r];

                      uint256_t rscript_h256;

                      const uint8_t *rscript = data_r;
                      int offset = n_length_r - kSHA256ByteSize;
                      if (unlikely(offset > 0)) {
                        rscript += offset;
                      } else {
                        memset(rscript_h256.v, 0, kSHA256ByteSize);
                        memcpy(rscript_h256.v, data_r, n_length_r);
                        rscript = (const uint8_t *)(&(rscript_h256.v));
                      }

                      auto i = gPublicKeyXMap.find(rscript);
                      if(unlikely(gPublicKeyXMap.end()!=i)) {
                        showHex(rscript, kSHA256ByteSize, false);
                        printf(" P\n");
                        nbBadP_aleady_in_R++;
                        fflush(stdout);
                      }

                      auto i_r = gRMap.find(rscript);
                      if(unlikely(gRMap.end()!=i_r)) {
                        if (i_r->second > 0) {
                          showHex(rscript, kSHA256ByteSize, false);
                          printf(" R\n");
                          nbBadR++;
                          fflush(stdout);
                        } else {
                          i_r->second += 1;
                        }
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

static ConfirmDupRP confirmDupRP;
