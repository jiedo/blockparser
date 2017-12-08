// Dump all outScript type


#include <util.h>
#include <common.h>
#include <errlog.h>
#include <string.h>
#include <callback.h>

typedef GoogMap<Hash160, uint64_t, Hash160Hasher, Hash160Equal>::Map TypeMap;

struct OutType:public Callback
{
    optparse::OptionParser parser;

    uint8_t *currHash;
    TypeMap typeMap;

    uint64_t bTime;

    uint64_t nbOutputs;
    uint64_t currBlock;
    uint64_t nThreshold;        // print no detail if overflow
    uint64_t nbDumped;
    const uint8_t *txStart;

    OutType()
    {
        parser
            .usage("")
            .version("")
            .description(
                "dump the details of each outscript type"
            )
            .epilog("")
        ;
    }

    virtual const char                   *name() const         { return "outType"; }
    virtual const optparse::OptionParser *optionParser() const { return &parser;  }
    virtual bool                         needTXHash() const    { return true;     }
    virtual bool                         needEdge() const      { return false;     }
    virtual void aliases(
        std::vector<const char*> &v
    ) const {
        v.push_back("outtype");
    }


    virtual int init(
        int argc,
        const char *argv[]
    ) {
        nbDumped = 0;
        nThreshold = 100;

        static uint8_t emptykey160[kRIPEMD160ByteSize] = { 0x52 };
        typeMap.setEmptyKey(emptykey160);

        /*
          0000000000000000000000000000000000004b6a 39151
          000000000000000000000000000000000000ac4b 989493
          0000000000000000000000000000000000874ba9 7656800
          00000000000000000000000000000000ae514b51 2225
          000000000000000000000000000000ac884ba976 300640055
          000000000000000000000000000000ae524b4b51 234637
          000000000000000000000000000000ae524b4b52 2896
          0000000000000000000000000000747069726373 1182
          0000000000000000000000000000ae534b4b4b51 285080
          0000000000000000000000000000ae534b4b4b52 2566
          0000000000000000000000000000ae534b4b4b53 1025

          0000000000000000000000000000000000000000 3
          000000000000000000000000000000000000004b 3
          0000000000000000000000000000000000000051 2
          000000000000000000000000000000000000006a 25
          0000000000000000000000000000000000000076 2
          0000000000000000000000000000000000000082 1
          00000000000000000000000000000000000000ac 1
          00000000000000000000000000000000000000ae 1
          00000000000000000000000000000000000000ff 1
          0000000000000000000000000000000000004b00 3
          0000000000000000000000000000000000004b4b 1
          0000000000000000000000000000000000005252 1
          00000000000000000000000000000000000091ae 1
          00000000000000000000000000000000004b0000 2
          00000000000000000000000000000000004b006a 24
          00000000000000000000000000000000004b4b6a 1
          00000000000000000000000000000000004b4ba8 1
          000000000000000000000000000000000051754b 2
          000000000000000000000000000000000075b14b 15
          0000000000000000000000000000000000767676 2
          0000000000000000000000000000000000874ba8 46
          0000000000000000000000000000000000874baa 6
          00000000000000000000000000000000008753a3 4
          0000000000000000000000000000000000ac4b00 4
          0000000000000000000000000000000051754b00 8
          0000000000000000000000000000000051757553 1
          00000000000000000000000000000000ae514b00 3
          00000000000000000000000000000000ae8b7c4b 1
          0000000000000000000000000000004b00000000 2
          00000000000000000000000000000051754b754b 1
          000000000000000000000000000000874ba8754b 2
          000000000000000000000000000000ac4b884ba9 1
          000000000000000000000000000000ac8800a976 23
          000000000000000000000000000000ac884baa76 1
          000000000000000000000000000000ae514b0051 2
          000000000000000000000000000000b0884ba976 1
          00000000000000000000000000004b4b4b4b4b6a 1
          000000000000000000000000000061ac884ba976 6
          00000000000000000000000000009bac4b7cac4b 1
          0000000000000000000000000000ac884b00a976 1
          0000000000000000000000000000acb0884ba976 1
          0000000000000000000000000000ae514b51754b 1
          0000000000000000000000000000ae524b4b0051 7
          000000000000000000000000004b624b6568546a 1
          00000000000000000000000000684b00004bff63 1
          00000000000000000000000000686a6751675163 1
          00000000000000000000000000754b00875d9393 1
          000000000000000000000000008752948858936e 1
          0000000000000000000000000087a6a7a8a9aa74 1
          000000000000000000000000009bac4b7c874ba9 1
          00000000000000000000000000ac874ba976754b 2
          00000000000000000000000000ac884ba976754b 4
          000000000000000000000000ac884ba975a97676 1
          000000000000000000000000ac884ba976754b00 3
          000000000000000000000000ac884ba976884baa 1
          000000000000000000000000ae534b4b004b0051 4
          000000000000000000000000ae554b4b4b4b4b53 1
          000000000000000000000068874baa67874baa63 1
          0000000000000000000000874ba8a8a8a8a8754b 1
          0000000000000000000000ae534b004b004b0051 5
          0000000000000000000068ac4b67ac4b884ba963 1
          00000000000000000000ac4b884ba869a54b4b82 3
          000000000000000000754b006c686a64875d9393 1
          0000000000000000009aac4b7c9bac4b7c874ba8 2
          00000000000000006984ac4b7c9bac4b7c874ba8 1
          00000000000000006cad4b6ba5605190699f0076 1
          000000000000000087a6a7a8a9aa8f69a0517682 1
          0000000000000000ae594b4b4b4b4b4b4b4b4b51 1
          0000000000000000ae594b4b4b4b4b4b4b4b4b59 1
          0000000000000068af524b4b5267af524b4b5263 1
          00000000000000754b000068874baa64874baa76 1
          00000000000068ac4b67874ba9884ba9884ba963 1
          000000000000ae527b7b52884ba9767c884ba976 1
          000000009bac4b7cad4b7c9a874ba87ca54b4b82 6
          00000068ac884ba97667874ba6a6754b639c5174 1
          0000ac4b68ad4b6775639a874ba87ca54b4b8276 2
          004b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b 1
          004b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b64 1
          004baa76686b5163874baa766b00684b6a638c74 1
          006487b65767b0884baa7563876153766b76b774 1
          00686a6476878c93528f686a6476879356945474 1
          0079549a874ba87953874ba879537cac4b7cac4b 3
          00884ba869a54b4b7d827c884ba869a54b4b7d82 1
          009353766c885294529093538f64874baa766b74 1
          00acacacacacacacacacacacacacacac884ba976 3
          00ae604b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b60 2
          00ae604b5e5d5c5b5a5958575655545352514b52 1
        */

        const char *knownOutScriptTypes[] = {"0000000000000000000000000000000000004b6a",
                                             "000000000000000000000000000000ac884ba976",
                                             "000000000000000000000000000000000000ac4b",
                                             "0000000000000000000000000000000000874ba9",
                                             "0000000000000000000000000000747069726373",

                                             "00000000000000000000000000000000ae514b51",

                                             "000000000000000000000000000000ae524b4b51",
                                             "000000000000000000000000000000ae524b4b52",

                                             "0000000000000000000000000000ae534b4b4b51",
                                             "0000000000000000000000000000ae534b4b4b52",
                                             "0000000000000000000000000000ae534b4b4b53",

        };

        //do not dump detail of known script type, by setting threshold overflow.
        for(int i=0; i!=sizeof(knownOutScriptTypes)/sizeof(char*); ++i)
          {
            const uint8_t *hexhash = (const uint8_t *)(knownOutScriptTypes[i]);
            uint160_t *type_new = (uint160_t *)allocHash160();
            fromHex(type_new->v, hexhash, kRIPEMD160ByteSize, true);
            typeMap[type_new->v] = nThreshold;
          }
        return 0;
    }


    virtual void startBlock(
        const Block *b,
        uint64_t
    ) {
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
    ) {
        txStart = p;
        currHash = (uint8_t *)hash;
        nbOutputs = 0;
    }


    static void showScriptInfo(
        const uint8_t   *outputScript,
        uint64_t        outputScriptSize
    ) {
        uint8_t type[128];
        const char *typeName = "other";
        uint8_t pubKeyHash[kSHA256ByteSize];
        int r = solveOutputScript(pubKeyHash, outputScript, outputScriptSize, type);
        const char *script_type_name[] = {
          "broken script generated by p2pool - coins lost",
          "couldn't parse script",
          "pays to hash160(pubKey)",
          "pays to explicit uncompressed pubKey",
          "pays to explicit compressed pubKey",
          "pays to hash160(script)",
          "pays to hash160(script)",
        };
        if (r >= -2 && r <=4) {
          typeName = script_type_name[r+2];
        }
        printf("   script: %s\n", typeName);

        if( 0<=r ) {
            uint8_t btcAddr[64];
            hash160ToAddr(btcAddr, pubKeyHash, (uint8_t)type[0]);
            printf("  address: %s\n", btcAddr);
        }
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

      if (likely(typeMap.end() != j)) { //found
        if (j->second++ > nThreshold)
          return;
        printf("\n%s    type: ", pr128(j->second).c_str());
      } else {
        uint160_t *type_new = (uint160_t *)allocHash160();
        memcpy(type_new->v, type, kRIPEMD160ByteSize);
        typeMap[type_new->v] = 1;
        printf("\n1    type: ");
      }
      showHex(type, sizeof(uint160_t));

      struct tm gmTime;
      time_t blockTime = bTime;
      gmtime_r(&blockTime, &gmTime);

      char timeBuf[256];
      asctime_r(&gmTime, timeBuf);

      size_t sz =strlen(timeBuf);
      if(0<sz) timeBuf[sz-1] = 0;

      printf("\n   txHash: ");
      showHex(currHash);
      printf("\n");

      printf("    block: %ld\n", currBlock-1);
      printf("     time: %ld (%s GMT)\n", bTime, timeBuf);
      printf(" spend[%ld]: %ld\n", nbOutputs-1, value);
      showScript(outputScript, outputScriptSize, 0, "        ");
      showScriptInfo(outputScript, outputScriptSize);

      ++nbDumped;
    }


    virtual void wrapup()
    {
        auto i = typeMap.begin();
        auto e = typeMap.end();
        printf("\n\n");
        printf("Type                                     Count\n");
        printf("---------------------------------------- ----------\n");

        while(i!=e) {
          showHex(i->first, sizeof(uint160_t));
          printf(" %s\n", pr128(i->second).c_str());
          ++i;
        }
        printf("\n");
        printf("Found %ld different types of outscript.\n", typeMap.size());
    }
};

static OutType outType;
