// Dump all outScript type


#include <util.h>
#include <common.h>
#include <errlog.h>
#include <string.h>
#include <callback.h>

typedef GoogMap<Hash160, uint64_t, Hash160Hasher, Hash160Equal>::Map TypeMap;

struct InType:public Callback
{
    optparse::OptionParser parser;

    uint8_t *currHash;
    TypeMap typeMap;
    bool include_gen_input;
    uint64_t bTime;
    size_t nbInputs;
    bool hasGenInput;
    uint64_t currBlock;
    uint64_t nThreshold;        // print no detail if overflow
    uint64_t nbDumped;
    const uint8_t *txStart;

    InType()
    {
        parser
            .usage("[options]")
            .version("")
            .description(
                "dump the details of each inscript type"
            )
            .epilog("")
        ;
        parser
            .add_option("-g", "--gen")
            .action("include_gen_input")
            .set_default(false)
            .help("print generated input script")
        ;

    }

    virtual const char                   *name() const         { return "inType"; }
    virtual const optparse::OptionParser *optionParser() const { return &parser;  }
    virtual bool                         needTXHash() const    { return true;     }
    virtual bool                         needEdge() const      { return false;     }
    virtual void aliases(
        std::vector<const char*> &v
    ) const {
        v.push_back("intype");
    }


    virtual int init(int argc, const char *argv[]) {
        optparse::Values &values = parser.parse_args(argc, argv);
        include_gen_input = values.get("gen");
        nbDumped = 0;
        nThreshold = 100;
        static uint8_t emptykey160[kRIPEMD160ByteSize] = { 0x52 };
        typeMap.setEmptyKey(emptykey160);
        // const char *knownInScriptTypes[] = {};
        // //do not dump detail of known script type, by setting threshold overflow.
        // for(int i=0; i!=sizeof(knownInScriptTypes)/sizeof(char*); ++i)
        //   {
        //     const uint8_t *hexhash = (const uint8_t *)(knownInScriptTypes[i]);
        //     uint160_t *type_new = (uint160_t *)allocHash160();
        //     fromHex(type_new->v, hexhash, kRIPEMD160ByteSize, true);
        //     typeMap[type_new->v] = nThreshold;
        //   }
        return 0;
    }


    virtual void startBlock(const Block *b, uint64_t) {
        const uint8_t *p = b->chunk->getData();
        SKIP(uint32_t, version, p);
        SKIP(uint256_t, prevBlkHash, p);
        SKIP(uint256_t, blkMerkleRoot, p);
        LOAD(uint32_t, blkTime, p);

        currBlock = b->height;
        bTime = blkTime;
    }


    virtual void startTX(const uint8_t *p, const uint8_t *hash, const uint8_t *txEnd) {
        txStart = p;
        currHash = (uint8_t *)hash;
        nbInputs = 0;
        hasGenInput = false;
    }


    virtual void startInput(const uint8_t *p) {
        static uint256_t gNullHash;
        bool isGenInput = (0==memcmp(gNullHash.v, p, sizeof(gNullHash)));
        if(isGenInput) {
            hasGenInput = true;
        }
        nbInputs++;
    }


    virtual void endInput(const uint8_t *pend, const uint8_t *upTXHash, uint64_t outputIndex, const uint8_t *downTXHash, uint64_t      inputIndex, const uint8_t *inputScript, uint64_t inputScriptSize) {
      if(!include_gen_input && hasGenInput) {
        return;
      }
      uint8_t type[20] = {0};
      int type_size = get_script_type(inputScript, inputScriptSize, type);
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
      printf("    input: %ld\n", nbInputs-1);
      showScript(inputScript, inputScriptSize, 0, "        ");
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
        printf("Found %ld different types of inscript.\n", typeMap.size());
    }
};

static InType inType;
