// Dump all outScript type


#include <util.h>
#include <common.h>
#include <errlog.h>
#include <string.h>
#include <callback.h>

typedef GoogMap<Hash160, uint128_t, Hash160Hasher, Hash160Equal>::Map TypeMap;

struct DumpOut:public Callback
{
    optparse::OptionParser parser;

    bool dump;
  uint8_t *currHash;
  TypeMap typeMap;

    bool isGenTX;
    uint64_t bTime;
    uint64_t valueIn;
    uint64_t valueOut;
    uint64_t nbInputs;
    uint64_t nbOutputs;
    uint64_t currBlock;
  uint64_t nThreshold;
    uint64_t nbDumped;
    const uint8_t *txStart;
    std::vector<uint160_t> igore_type_hashes;
  uint64_t n_total_dumped = 1000;
  int n_minimum_type = -3;
  int n_undumped_type[10] = {10, 10, 1000,  10,10,10,  10,  1,  2,2,};

    DumpOut()
    {
        parser
            .usage("[list of transaction hashes]")
            .version("")
            .description(
                "dumpp all the details of  the list of specified transactions"
            )
            .epilog("")
        ;
    }

    virtual const char                   *name() const         { return "dumpOut"; }
    virtual const optparse::OptionParser *optionParser() const { return &parser;  }
    virtual bool                         needTXHash() const    { return true;     }

    virtual void aliases(
        std::vector<const char*> &v
    ) const
    {
        v.push_back("outinfo");
        // v.push_back("txshow");
        // v.push_back("showtx");
        // v.push_back("txdetails");
    }

    virtual int init(
        int argc,
        const char *argv[]
    )
    {
        nbDumped = 0;
        nThreshold = 1000;

        static uint8_t emptykey160[kRIPEMD160ByteSize] = { 0x52 };
        typeMap.setEmptyKey(emptykey160);

        const char *knownOutScriptTypes[] = {"000000000000000000000000000000ac884ba976",
                                          "000000000000000000000000000000000000ac4b",
                                          "0000000000000000000000000000000000874ba9",
                                          "0000000000000000000000000000747069726373",

                                          "00000000000000000000000000000000ae514b51",

                                          "000000000000000000000000000000ae524b4b51",
                                          "000000000000000000000000000000ae524b4b52",

                                          "0000000000000000000000000000ae534b4b4b51",
                                          "0000000000000000000000000000ae534b4b4b52",
                                          "0000000000000000000000000000ae534b4b4b53"
        };

        //do not dump detail of known script type, by setting threshold overflow.
        for(int i=0; i!=10; ++i)
          {
            const uint8_t *hexhash = (const uint8_t *)(knownOutScriptTypes[i]);
            uint160_t *type_new = (uint160_t *)allocHash160();
            fromHex(type_new->v, hexhash, kRIPEMD160ByteSize, true);
            typeMap[type_new->v] = nThreshold;
          }

        for(int i=0; i!=10; ++i)
          {
            const uint8_t *hexhash = (const uint8_t *)(knownOutScriptTypes[i]);
            uint160_t type;
            fromHex(type.v, hexhash, kRIPEMD160ByteSize, true);

            auto j = typeMap.find(type.v);
            if (typeMap.end() == j)
              {
                printf("!!! init hex, error: %d, %s\n", i, knownOutScriptTypes[i]);
                exit(0);
              }
          }

        return 0;
    }

    virtual void startBlock(
        const Block *b,
        uint64_t
    )
    {
        currBlock = b->height;
        const uint8_t *p = b->chunk->getData();
        SKIP(uint32_t, version, p);
        SKIP(uint256_t, prevBlkHash, p);
        SKIP(uint256_t, blkMerkleRoot, p);
        LOAD(uint32_t, blkTime, p);
        bTime = blkTime;
    }

    virtual void startTX(
        const uint8_t *p,
        const uint8_t *hash,
        const uint8_t *txEnd
    )
    {
        txStart = p;
        currHash = (uint8_t *)hash;
        nbInputs = 0;
        nbOutputs = 0;

        dump = false;

        if(dump) {

            struct tm gmTime;
            time_t blockTime = bTime;
            gmtime_r(&blockTime, &gmTime);

            char timeBuf[256];
            asctime_r(&gmTime, timeBuf);

            size_t sz =strlen(timeBuf);
            if(0<sz) timeBuf[sz-1] = 0;

            LOAD(uint32_t, version, p);

            printf("TX = {\n\n");
            printf("    version = %" PRIu32 "\n", version);
            printf("    minted in block = %" PRIu64 "\n", currBlock-1);
            printf("    mint time = %" PRIu64 " (%s GMT)\n", bTime, timeBuf);
            printf("    txHash = ");
            showHex(hash);
            printf("\n\n");
        }
    }

    virtual void startInputs(
        const uint8_t *p
    )
    {
    }

    virtual void endInputs(
        const uint8_t *p
    )
    {
    }

    static void canonicalHexDump(
        const uint8_t *p,
               size_t size,
           const char *indent
    )
    {
        const uint8_t *s =        p;
        const uint8_t *e = size + p;
        while(p<e) {

            printf(
                "%s%06x: ",
                indent,
                (int)(p-s)
            );

            const uint8_t *lp = p;
            const uint8_t *np = 16 + p;
            const uint8_t *le = std::min(e, 16+p);
            while(lp<np) {
                if(lp<le) printf("%02x ", (int)*lp);
                else      printf("   ");
                ++lp;
            }

            lp = p;
            while(lp<le) {
                int c = *(lp++);
                printf("%c", isprint(c) ? c : '.');
            }

            printf("\n");
            p = np;
        }
    }

    virtual void startInput(
        const uint8_t *p
    )
    {
        if(dump) {
          nbInputs++;
            static uint256_t gNullHash;
            LOAD(uint256_t, upTXHash, p);
            LOAD(uint32_t, upOutputIndex, p);
            LOAD_VARINT(inputScriptSize, p);
            isGenTX = (0==memcmp(gNullHash.v, upTXHash.v, sizeof(gNullHash)));
            if(isGenTX) {
              printf(
                     "    input[%" PRIu64 "] = {\n",
                     nbInputs
                     );

                uint64_t reward = getBaseReward(currBlock);
                printf("        generation transaction\n");
                printf("        based on block height, reward = %.8f\n", 1e-8*reward);
                printf("        hex dump of coinbase follows:\n\n");
                canonicalHexDump(p, inputScriptSize, "        ");
                valueIn += reward;
            }
        }
    }

    static void showScriptInfo(
        const uint8_t   *outputScript,
        uint64_t        outputScriptSize
    )
    {
        uint8_t type[128];
        const char *typeName = "unknown";
        uint8_t pubKeyHash[kSHA256ByteSize];
        int r = solveOutputScript(pubKeyHash, outputScript, outputScriptSize, type);

        switch(r) {
            case 0: {
                typeName = "pays to hash160(pubKey)";
                break;
            }
            case 1: {
                typeName = "pays to explicit uncompressed pubKey";
                break;
            }
            case 2: {
                typeName = "pays to explicit compressed pubKey";
                break;
            }
            case 3: {
                typeName = "pays to hash160(script)";
                break;
            }
            case 4: {
                typeName = "pays to hash160(script)";
                break;
            }
            case -2: {
                typeName = "broken script generated by p2pool - coins lost";
                break;
            }
            case -1: {
                typeName = "couldn't parse script";
                break;
            }
        }

        printf("\n");
        printf("        script type = %s\n", typeName);

        if(0<=r) {
            uint8_t btcAddr[64];
            hash160ToAddr(btcAddr, pubKeyHash);
            printf("        script pays to address %s\n", btcAddr);
        }
    }

    // virtual void edge(
    //     uint64_t      value,
    //     const uint8_t *upTXHash,
    //     uint64_t      outputIndex,
    //     const uint8_t *outputScript,
    //     uint64_t      outputScriptSize,
    //     const uint8_t *downTXHash,
    //     uint64_t      inputIndex,
    //     const uint8_t *inputScript,
    //     uint64_t      inputScriptSize
    // )
    // {
    //     if(dump) {
    //         uint8_t buf[1 + 2*kSHA256ByteSize];
    //         toHex(buf, upTXHash);
    //         printf("        outputIndex = %" PRIu64 "\n", outputIndex);
    //         printf("        value = %.8f\n", value*1e-8);
    //         printf("        upTXHash = %s\n\n", buf);
    //         printf("        # challenge answer script, bytes=%" PRIu64 " (on downstream input) =\n", inputScriptSize);
    //         showScript(inputScript, inputScriptSize, 0, "        ");
    //         printf("                           ||\n");
    //         printf("                           VV\n");
    //         printf("        # challenge script, bytes=%" PRIu64 " (on upstream output)=\n", outputScriptSize);
    //         showScript(outputScript, outputScriptSize, 0, "        ");
    //         showScriptInfo(outputScript, outputScriptSize);
    //         valueIn += value;

    //     }
    // }

    virtual void endInput(
                          const uint8_t *pend,
                          const uint8_t *upTXHash,
                          uint64_t      outputIndex,
                          const uint8_t *downTXHash,
                          uint64_t      inputIndex,
                          const uint8_t *inputScript,
                          uint64_t      inputScriptSize
                          ){

        if(dump && isGenTX) {
            printf("    }\n");
        }
    }

    virtual void startOutputs(
        const uint8_t *p
    )
    {
    }

    virtual void endOutputs(
        const uint8_t *p
    )
    {
    }

    virtual void startOutput(
        const uint8_t *p
    )
    {

        // if(dump) {
        //     printf(
        //         "\n"
        //         "    output[%" PRIu64 "] = {\n\n",
        //         nbOutputs++
        //     );
        // }
    }

    virtual void endOutput(
        const uint8_t *p,                   // Pointer to TX output raw data
        uint64_t      value,                // Number of satoshis on this output
        const uint8_t *txHash,              // sha256 of the current transaction
        uint64_t      outputIndex,          // Index of this output in the current transaction
        const uint8_t *outputScript,        // Raw script (challenge to would-be spender) carried by this output
        uint64_t      outputScriptSize      // Byte size of raw script
    )
    {
      nbOutputs++;
      if (value==0) return;

      uint8_t type[20] = {0};

      int type_size = get_script_type(outputScript, outputScriptSize, type);
      auto j = typeMap.find(type);

      if (typeMap.end() != j) //is_fond
        {
          if (j->second++ > nThreshold)
            return;
          printf("\n%s    type:", pr128(j->second).c_str());
        }
      else
        {
          uint160_t *type_new = (uint160_t *)allocHash160();
          memcpy(type_new->v, type, kRIPEMD160ByteSize);
          typeMap[type_new->v] = 1;
          printf("\n1    type:");
        }

      showHex(type, sizeof(uint160_t));

      const char *typeName = "unknown";
      uint8_t pubKeyHash[kSHA256ByteSize];
      int r = solveOutputScript(pubKeyHash, outputScript, outputScriptSize, type);
      switch(r) {
      case 0: {
        typeName = "pays to hash160(pubKey)";
        break;
      }
      case 1: {
        typeName = "pays to explicit uncompressed pubKey";
        break;
      }
      case 2: {
        typeName = "pays to explicit compressed pubKey";
        break;
      }
      case 3: {
        typeName = "pays to hash160(script)";
        break;
      }
      case 4: {
        typeName = "pays to hash160(script)";
        break;
      }
      case -2: {
        typeName = "broken script generated by p2pool - coins lost";
        break;
      }
      case -1: {
        typeName = "couldn't parse script";
        break;
      }
      }

      struct tm gmTime;
      time_t blockTime = bTime;
      gmtime_r(&blockTime, &gmTime);

      char timeBuf[256];
      asctime_r(&gmTime, timeBuf);

      size_t sz =strlen(timeBuf);
      if(0<sz) timeBuf[sz-1] = 0;

      LOAD(uint32_t, version, p);

      printf("\ntxHash = ");
      showHex(currHash);
      printf("\n");
      printf("    version = %" PRIu32 "\n", version);
      printf("    minted in block = %" PRIu64 "\n", currBlock-1);
      printf("    mint time = %" PRIu64 " (%s GMT)\n", bTime, timeBuf);

      printf("        output[%" PRIu64 "] = %" PRIu64 ", %s\n", nbOutputs-1, value, typeName);
      showScript(outputScript, outputScriptSize, 0, "        ");
      if(0<=r) {
        uint8_t btcAddr[64];
        hash160ToAddr(btcAddr, pubKeyHash);
        printf("        script pays to address %s\n", btcAddr);
      }

      ++nbDumped;

        if(dump) {
            printf("        value = %.8f\n", value*1e-8);
            printf("        challenge script, bytes=%" PRIu64 " :\n", outputScriptSize);
            showScript(outputScript, outputScriptSize, 0, "        ");
            showScriptInfo(outputScript, outputScriptSize);
            printf("    }\n\n");
            valueOut += value;
        }
    }

    virtual void endTX(
        const uint8_t *p
    )
    {
        if(nbDumped==n_total_dumped) {
            exit(0);
        }

    }

    virtual void wrapup()
    {
        auto i = typeMap.begin();
        auto e = typeMap.end();
        printf("Found %" PRIu64 " different script types.\n", typeMap.size());
        printf("TYPE                                     N\n");
        printf("---------------------------------------- ----------\n");

        while(i!=e) {
          showHex(i->first, sizeof(uint160_t));
          printf(" %s\n", pr128(i->second).c_str());
          ++i;
        }
    }




};

static DumpOut dumpOut;
