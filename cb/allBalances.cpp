// Dump balance of all addresses ever used in the blockchain

#include <util.h>
#include <common.h>
#include <errlog.h>
#include <option.h>
#include <rmd160.h>
#include <sha256.h>
#include <callback.h>

#include <vector>
#include <string.h>

struct Addr;
static uint8_t hash160_emptykey[kRIPEMD160ByteSize] = { 0x52 };
static uint8_t hash160_deletedkey[kRIPEMD160ByteSize] = { 0x00 };

typedef GoogMap<Hash160, Addr*, Hash160Hasher, Hash160Equal>::Map AddrMap;
typedef GoogMap<Hash160, int, Hash160Hasher, Hash160Equal>::Map RestrictMap;

struct Addr
{
    uint64_t sum;
    uint32_t nbIn;
    uint32_t nbOut;
    uint160_t hash;
    uint32_t type;
};

static std::vector<uint8_t *> vec_addr;
template<> std::vector<uint8_t *> PagedAllocator<Addr>::reuse_pool = vec_addr;
template<> uint32_t PagedAllocator<Addr>::total_malloc = 0;
template<> uint8_t *PagedAllocator<Addr>::pool = 0;
template<> uint8_t *PagedAllocator<Addr>::poolEnd = 0;
static inline Addr *allocAddr() { return (Addr*)PagedAllocator<Addr>::alloc(); }
static inline int freeAddr(Addr *ptr) { return  PagedAllocator<Addr>::free((uint8_t*)ptr);}

struct AllBalances:public Callback
{
    bool detailed;
    int64_t limit;
    uint64_t offset;
    int64_t nbTX;
    int64_t cutoffBlock;
    int64_t currBlock;
    optparse::OptionParser parser;

    AddrMap addrMap;
    uint32_t blockTime;
    RestrictMap restrictMap;
    std::vector<uint160_t> restricts;

    AllBalances()
    {
        parser.usage("[options] [list of addresses to restrict output to]")
            .version("")
            .description("dump the balance for all addresses that appear in the blockchain")
            .epilog("");
        parser.add_option("-a", "--atBlock")
            .action("store")
            .type("int")
            .set_default(-1)
            .help("only take into account transactions in blocks strictly older than <block> (default: all)");
        parser.add_option("-l", "--limit")
            .action("store")
            .type("int")
            .set_default(-1)
            .help("limit output to top N balances, (default : output all addresses)");
    }

    virtual const char                   *name() const         { return "allBalances"; }
    virtual const optparse::OptionParser *optionParser() const { return &parser;       }
    virtual bool                         needTXHash() const    { return true;          }
    virtual void aliases(std::vector<const char*> &v) const    { v.push_back("balances"); }

    virtual int init(int argc, const char *argv[]) {
        nbTX = 0;
        offset = 0;
        currBlock = 0;

        addrMap.setEmptyKey(hash160_emptykey);
        addrMap.setDeleteKey(hash160_deletedkey);

        addrMap.resize(15 * 1000 * 1000);

        optparse::Values &values = parser.parse_args(argc, argv);
        cutoffBlock = values.get("atBlock");
        limit = values.get("limit");

        auto args = parser.args();
        for(size_t i=1; i<args.size(); ++i) {
            loadKeyList(restricts, args[i].c_str());
        }
        if(0<=cutoffBlock) {
            info("only taking into account transactions before block %" PRIu64 "\n", cutoffBlock);
        }
        if(0!=restricts.size()) {
            info("restricting output to %" PRIu64 " addresses ...\n", (uint64_t)restricts.size());
            auto e = restricts.end();
            auto i = restricts.begin();
            restrictMap.setEmptyKey(hash160_emptykey);
            while(e!=i) {
                const uint160_t &h = *(i++);
                restrictMap[h.v] = 1;
            }
        }
        return 0;
    }

    void move(const uint8_t *script, uint64_t scriptSize, const uint8_t *upTXHash, int64_t outputIndex, int64_t value) {
        // last 2 params are not used
        uint8_t addrType[4];
        uint160_t pubKeyHash;
        int outputType = solveOutputScript(pubKeyHash.v, script, scriptSize, addrType);
        if(unlikely(outputType<0))
            return;
        if(0!=restrictMap.size()) {
            auto r = restrictMap.find(pubKeyHash.v);
            if(restrictMap.end()==r) {
                return;
            }
        }
        Addr *addr;
        auto i = addrMap.find(pubKeyHash.v);
        if(unlikely(addrMap.end()!=i)) {
            addr = i->second;
        } else {
            addr = allocAddr();
            memcpy(addr->hash.v, pubKeyHash.v, kRIPEMD160ByteSize);
            addr->type = (uint32_t)addrType[0];
            addr->nbOut = 0;
            addr->nbIn = 0;
            addr->sum = 0;
            addrMap[addr->hash.v] = addr;
        }
        if(0<value) {
            ++(addr->nbIn);
        } else {
            ++(addr->nbOut);
        }
        if (unlikely(value == 0)) {
            // uint8_t buf[64];
            // hash160ToAddr(buf, addr->hash.v, addr->type);
            // info("have zero income: %s\n", buf);
            return;
        }
        addr->sum += value;
        if(addr->sum == 0) {
            addrMap.erase(i);
            freeAddr(addr);
        }
    }

    virtual void endOutput(const uint8_t *p, uint64_t value, const uint8_t *txHash, uint64_t outputIndex, const uint8_t *outputScript, uint64_t outputScriptSize) {
        move(outputScript, outputScriptSize, txHash, outputIndex, value);
    }

    virtual void edge(uint64_t value, const uint8_t *upTXHash, uint64_t outputIndex, const uint8_t *outputScript, uint64_t outputScriptSize, const uint8_t *downTXHash, uint64_t inputIndex, const uint8_t *inputScript, uint64_t inputScriptSize, const uint8_t *downWitness) {
        move(outputScript, outputScriptSize, upTXHash, outputIndex, -(int64_t)value);
    }

    virtual void wrapup() {
        auto s = addrMap.begin();
        auto e = addrMap.end();
        uint64_t nbRestricts = (uint64_t)restrictMap.size();
        if(0==nbRestricts) info("dumping all balances ...");
        else               info("dumping balances for %" PRIu64 " addresses ...", nbRestricts);

        int64_t i = 0;
        int64_t nonZeroCnt = 0;
        while(s != e) {
            if(0 <= limit && limit <= i)
                break;
            Addr *addr = s->second;
            s++;
            printf("%.8f\t", 1e-8*addr->sum);
            if(0 < addr->sum)
                ++nonZeroCnt;
            uint8_t buf[64];
            hash160ToAddr(buf, addr->hash.v, addr->type);
            printf("%s\t%d\t%d\n", buf, addr->nbIn, addr->nbOut);
            ++i;
        }
        info("done\n");
        info("found %" PRIu64 " addresses with non zero balance", nonZeroCnt);
        info("found %" PRIu64 " addresses in total", (uint64_t)addrMap.size());
        info("shown:%" PRIu64 " addresses", (uint64_t)i);
        printf("\n");
    }

    virtual void startTX(const uint8_t *p, const uint8_t *hash, const uint8_t *txEnd) {
        ++nbTX;
    }

    virtual void startBlock(const Block *b, uint64_t chainSize ) {
        const uint8_t *p = b->chunk->getData();
        SKIP(uint32_t, version, p);
        SKIP(uint256_t, prevBlkHash, p);
        SKIP(uint256_t, blkMerkleRoot, p);
        LOAD(uint32_t, bTime, p);
        blockTime = bTime;

        currBlock = b->height;
        if(0<=cutoffBlock && cutoffBlock<=currBlock) {
            wrapup();
            exit(0);
        }
    }
};

static AllBalances allBalances;
