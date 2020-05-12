
// Dump everything known about a TX

#include <util.h>
#include <common.h>
#include <errlog.h>
#include <string.h>
#include <callback.h>

typedef GoogMap<Hash256, int, Hash256Hasher, Hash256Equal >::Map TxMap;

struct DumpTX:public Callback
{
    optparse::OptionParser parser;

    bool dump;
    TxMap txMap;
    bool isGenTX;
    uint64_t bTime;
    uint64_t valueIn;
    uint64_t valueOut;
    uint64_t nbInputs;
    uint64_t nbOutputs;
    uint64_t currBlock;
    uint32_t txVersion;
    uint64_t nbDumped;
    const uint8_t *txStart;
    std::vector<uint256_t> rootHashes;

    DumpTX()
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

    virtual const char                   *name() const         { return "dumpTX"; }
    virtual const optparse::OptionParser *optionParser() const { return &parser;  }
    virtual bool                         needTXHash() const    { return true;     }
    virtual bool                         needEdge() const    { return false;     }
    virtual void aliases(
        std::vector<const char*> &v
    ) const
    {
        v.push_back("txinfo");
        v.push_back("txshow");
        v.push_back("showtx");
        v.push_back("txdetails");
    }

    virtual int init(
        int        argc,
        const char *argv[]
    )
    {
        nbDumped = 0;

        optparse::Values &values = parser.parse_args(argc, argv);

        auto args = parser.args();
        for(size_t i=1; i<args.size(); ++i) {
            loadHash256List(rootHashes, args[i].c_str());
        }

        if(0<rootHashes.size()) {
            info("dumping %d transactions\n", (int)rootHashes.size());
        } else {
            const char *defaultTX = "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"; // Expensive pizza
            warning("no TX hashes specified, using the famous 10K pizza TX");
            loadHash256List(rootHashes, defaultTX);
        }

        static uint8_t empty[kSHA256ByteSize] = { 0x42 };
        txMap.setEmptyKey(empty);

        for(auto const &txHash : rootHashes) {
            txMap[txHash.v] = 1;
        }

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

    virtual void startTX(
        const uint8_t *p,
        const uint8_t *hash,
        const uint8_t *txEnd
    )
    {
        valueIn = 0;
        valueOut = 0;
        txStart = p;
        nbInputs = 0;
        nbOutputs = 0;
        dump = !hash or (txMap.end()!=txMap.find(hash));
        if(dump) {

            struct tm gmTime;
            time_t blockTime = bTime;
            gmtime_r(&blockTime, &gmTime);

            char timeBuf[256];
            asctime_r(&gmTime, timeBuf);

            size_t sz =strlen(timeBuf);
            if(0<sz) timeBuf[sz-1] = 0;

            LOAD(uint32_t, version, p);

            printf("TX = {\n");
            printf("    version = %" PRIu32 "\n", version);
            printf("    minted in block = %" PRIu64 "\n", currBlock-1);
            printf("    mint time = %" PRIu64 " (%s GMT)\n", bTime, timeBuf);
            printf("    txHash = ");
            if (hash)
                showHex(hash);
            printf("\n");
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

    virtual void startWitness(
        const uint8_t *p
    )
    {
        if(dump) {
            LOAD_VARINT(witScriptSize, p);
            printf("segwit len: %lu\n", witScriptSize);
            showScript(p, witScriptSize, 0, "        ");
        }
    }

    virtual void startInput(
        const uint8_t *p
    )
    {
        if(dump) {
            printf(
                "    input[%" PRIu64 "] = {\n",
                nbInputs++
            );

            static uint256_t gNullHash;
            LOAD(uint256_t, upTXHash, p);
            LOAD(uint32_t, upOutputIndex, p);
            LOAD_VARINT(inputScriptSize, p);
            isGenTX = (0==memcmp(gNullHash.v, upTXHash.v, sizeof(gNullHash)));
            if(isGenTX) {
                uint64_t reward = getBaseReward(currBlock);
                printf("        generation transaction\n");
                printf("        based on block height, reward = %.8f\n", 1e-8*reward);
                printf("        hex dump of coinbase follows:\n");
                canonicalHexDump(p, inputScriptSize, "        ");
                valueIn += reward;
            }

            uint8_t buf[1 + 2*kSHA256ByteSize];
            toHex(buf, upTXHash.v);
            printf("        outputIndex = %d\n", upOutputIndex);
            printf("        upTXHash = %s\n\n", buf);
            printf("        # challenge answer script, bytes=%" PRIu64 ", (on downstream input) ", inputScriptSize);
            showScript(p, inputScriptSize, 0, "        ");
        }
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
    )
    {
        if(dump) {
            uint8_t buf[1 + 2*kSHA256ByteSize];
            toHex(buf, upTXHash);
            printf("        outputIndex = %" PRIu64 "\n", outputIndex);
            printf("        value = %.8f\n", value*1e-8);
            printf("        upTXHash = %s\n\n", buf);
            printf("        # challenge answer script, bytes=%" PRIu64 " (on downstream input) =\n", inputScriptSize);
            showScript(inputScript, inputScriptSize, 0, "        ");
            printf("                           ||\n");
            printf("                           VV\n");
            printf("        # challenge script, bytes=%" PRIu64 " (on upstream output)=\n", outputScriptSize);
            showScript(outputScript, outputScriptSize, 0, "        ");
            showScriptInfo(outputScript, outputScriptSize);
            valueIn += value;

        }
    }

    virtual void endInput(
                          const uint8_t *pend,
                          const uint8_t *upTXHash,
                          uint64_t      outputIndex,
                          const uint8_t *downTXHash,
                          uint64_t      inputIndex,
                          const uint8_t *inputScript,
                          uint64_t      inputScriptSize
                          )
    {
        if(dump) {
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
        if(dump) {
            printf(
                "    output[%" PRIu64 "] = {\n",
                nbOutputs++
            );
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
        if(dump) {
            printf("        value = %.8f\n", value*1e-8);
            printf("        challenge script, bytes=%" PRIu64 ", ", outputScriptSize);
            showScript(outputScript, outputScriptSize, 0, "        ");
            showScriptInfo(outputScript, outputScriptSize);
            printf("    }\n");
            valueOut += value;
        }
    }

    virtual void endTX(
        const uint8_t *p
    )
    {
        if(dump) {
            LOAD(uint32_t, lockTime, p);
            printf("    nbInputs = %" PRIu64 "\n", (uint64_t)nbInputs);
            printf("   nbOutputs = %" PRIu64 "\n", (uint64_t)nbOutputs);
            printf("    byteSize = %" PRIu64 "\n", (uint64_t)(p - txStart));
            printf("    lockTime = %" PRIu32 "\n", (uint32_t)lockTime);
            printf("     valueIn =  %.8f\n", valueIn*1e-8);
            printf("    valueOut =  %.8f\n", valueOut*1e-8);
            if(!isGenTX) {
                printf("        fees =  %.8f\n", (valueIn-valueOut)*1e-8);
            }
            printf("}\n");
            ++nbDumped;
        }

        // if(nbDumped==txMap.size()) {
        //     exit(0);
        // }
    }
};

static DumpTX dumpTX;
