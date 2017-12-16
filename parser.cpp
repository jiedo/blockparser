
#include <util.h>
#include <common.h>
#include <errlog.h>
#include <callback.h>

#include <string>
#include <vector>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>


typedef GoogMap<Hash256, Chunk*, Hash256Hasher, Hash256Equal>::Map::iterator TXIterator;
typedef GoogMap<Hash256, Chunk*, Hash256Hasher, Hash256Equal>::Map TXOMap;
typedef GoogMap<Hash256, Block*, Hash256Hasher, Hash256Equal>::Map BlockMap;

static bool gNeedTXHash;
static bool gNeedEdge;
static Callback *gCallback;

static std::vector<Map> mapVec;

static uint8_t map_data_cache[256*1024*1024];
static int blockMapCacheFD;
static size_t blockMapCacheSize;
static std::string blockMapCacheFileName;

uint64_t g_n_tx_reuse;
static TXIterator giCurTXOMap;

static TXOMap gTXOMap;
static BlockMap gBlockMap;
static uint8_t empty[kSHA256ByteSize] = { 0x42 };
static uint8_t hash256_deleted[kSHA256ByteSize] = { 0x00 };

static Block *gMaxBlock;
static Block *gNullBlock;
static int64_t gMaxHeight;
static uint64_t gChainSize;
static uint256_t gNullHash;

#if defined BITCOIN
static const size_t gHeaderSize = 80;
static auto gCoinDirName = "/.bitcoin/";
static const uint32_t gExpectedMagic = 0xd9b4bef9;
#endif


#define DO(x) x
static inline void startBlock(const uint8_t *p) { DO(gCallback->startBlock(p)); }
static inline void endBlock(const uint8_t *p) { DO(gCallback->endBlock(p)); }
static inline void startTXs(const uint8_t *p) { DO(gCallback->startTXs(p)); }
static inline void endTXs(const uint8_t *p) { DO(gCallback->endTXs(p)); }
static inline void startTX(const uint8_t *p, const uint8_t *hash, const uint8_t *txEnd) { DO(gCallback->startTX(p,hash, txEnd)); }
static inline void endTX(const uint8_t *p) { DO(gCallback->endTX(p)); }
static inline void startInputs(const uint8_t *p) { DO(gCallback->startInputs(p)); }
static inline void endInputs(const uint8_t *p) { DO(gCallback->endInputs(p)); }
static inline void startInput(const uint8_t *p) { DO(gCallback->startInput(p)); }
static inline void startWitnesses(const uint8_t *p) { DO(gCallback->startWitnesses(p)); }
static inline void endWitnesses(const uint8_t *p) { DO(gCallback->endWitnesses(p)); }
static inline void startWitness(const uint8_t *p) { DO(gCallback->startWitness(p)); }
static inline void startOutputs(const uint8_t *p) { DO(gCallback->startOutputs(p)); }
static inline void endOutputs(const uint8_t *p) { DO(gCallback->endOutputs(p)); }
static inline void startOutput(const uint8_t *p) { DO(gCallback->startOutput(p)); }
static inline void start(const Block *s, const Block *e) { DO(gCallback->start(s, e)); }
#undef DO


static inline void startMap(const uint8_t *p) { gCallback->startMap(p); }
static inline void endMap(const uint8_t *p) { gCallback->endMap(p); }
static inline void startBlock(const Block *b) { gCallback->startBlock(b, gChainSize); }
static inline void endBlock(const Block *b) { gCallback->endBlock(b); }


static inline void endOutput(const uint8_t *p, uint64_t value, const uint8_t *txHash, uint64_t outputIndex, const uint8_t *outputScript, uint64_t outputScriptSize) {
    gCallback->endOutput(p, value, txHash, outputIndex, outputScript, outputScriptSize);
}


static inline void endInput( const uint8_t *pend, const uint8_t *upTXHash, uint64_t outputIndex, const uint8_t *downTXHash, uint64_t inputIndex, const uint8_t *inputScript, uint64_t inputScriptSize) {
    gCallback->endInput(pend, upTXHash, outputIndex, downTXHash, inputIndex, inputScript, inputScriptSize);
}


static inline void edge(uint64_t value, const uint8_t *upTXHash, uint64_t outputIndex, const uint8_t *outputScript, uint64_t outputScriptSize, const uint8_t *downTXHash, uint64_t inputIndex, const uint8_t *inputScript, uint64_t inputScriptSize) {
    gCallback->edge(value, upTXHash, outputIndex, outputScript, outputScriptSize, downTXHash, inputIndex, inputScript, inputScriptSize);
}


template<bool skip, bool fullContext>
static void parseOutput( const uint8_t *&p, const uint8_t *txHash, uint64_t outputIndex, const uint8_t *downTXHash, uint64_t downInputIndex, const uint8_t *downInputScript, uint64_t downInputScriptSize, bool found=false, uint64_t nbOutputs=1) {
    if(!skip && !fullContext) {
        startOutput(p);
    }
    LOAD(uint64_t, value, p);
    LOAD_VARINT(outputScriptSize, p);
    auto outputScript = p;
    p += outputScriptSize;
    if(!skip && fullContext && gNeedEdge && found) {
        edge(value, txHash, outputIndex, outputScript, outputScriptSize, downTXHash, downInputIndex, downInputScript, downInputScriptSize);

        auto i = giCurTXOMap;
        if (nbOutputs == (++(i->second->count))) {
            freeHash256((uint8_t*)i->first);
            i->second->releaseData();
            Chunk::release(i->second);
            gTXOMap.erase(i);
            g_n_tx_reuse++;
        }
    }
    if(!skip && !fullContext) {
        endOutput(p, value, txHash, outputIndex, outputScript, outputScriptSize);
    }
}


template<bool skip, bool fullContext>
static void parseOutputs(const uint8_t *&p, const uint8_t *txHash, uint64_t stopAtIndex=-1, const uint8_t *downTXHash=0, uint64_t downInputIndex=0, const uint8_t *downInputScript=0, uint64_t downInputScriptSize=0) {
    if(!skip && !fullContext) {
        startOutputs(p);
    }
    LOAD_VARINT(nbOutputs, p);
    for(uint64_t outputIndex=0; outputIndex<nbOutputs; ++outputIndex) {
        auto found = (fullContext && !skip && (stopAtIndex==outputIndex));
        parseOutput<skip, fullContext>(p, txHash, outputIndex, downTXHash, downInputIndex, downInputScript, downInputScriptSize, found, nbOutputs);
        if(found) {
            break;
        }
    }
    if(!skip && !fullContext) {
        endOutputs(p);
    }
}


template< bool skip >
static void parseInput( const Block *block, const uint8_t *&p, const uint8_t *txHash, uint64_t inputIndex) {
    if(!skip) {
        startInput(p);
    }
    auto upTXHash = p;
    const Chunk *upTX = 0;
    if(gNeedTXHash && gNeedEdge && !skip) {
        auto isGenTX = (0==memcmp(gNullHash.v, upTXHash, sizeof(gNullHash)));
        if(likely(false==isGenTX)) {
            auto i = gTXOMap.find(upTXHash);
            if(unlikely(gTXOMap.end()==i)) {
                errFatal("failed to locate upstream transaction");
            }
            upTX = i->second;
            giCurTXOMap = i;
        }
    }
    SKIP(uint256_t, dummyUpTXhash, p);
    LOAD(uint32_t, upOutputIndex, p);
    LOAD_VARINT(inputScriptSize, p);
    auto inputScript = p;
    if(!skip && 0!=upTX) {
        auto upTXOutputs = upTX->getData();
        parseOutputs<false, true>(upTXOutputs, upTXHash, upOutputIndex, txHash, inputIndex, inputScript, inputScriptSize);
    }
    p += inputScriptSize;
    SKIP(uint32_t, sequence, p);
    if(!skip) {
        endInput(p, upTXHash, upOutputIndex, txHash, inputIndex, inputScript, inputScriptSize);
    }
}


template<bool skip>
static uint64_t parseInputs(const Block *block, const uint8_t *&p, const uint8_t *txHash) {
    if(!skip) {
        startInputs(p);
    }
    LOAD_VARINT(nbInputs, p);
    for(uint64_t inputIndex=0; inputIndex<nbInputs; ++inputIndex) {
        parseInput<skip>(block, p, txHash, inputIndex);
    }
    if(!skip) {
        endInputs(p);
    }
    return nbInputs;
}


template<bool skip>
static void parseWitness(const Block *block, const uint8_t *&p) {
    if(!skip) {
        startWitness(p);
    }
    LOAD_VARINT(witScriptSize, p);
    p += witScriptSize;
}


template<bool skip>
static void parseWitnesses(const Block *block, const uint8_t *&p) {
    if(!skip) {
        startWitnesses(p);
    }
    LOAD_VARINT(nbWitnesses, p);
    for(uint64_t witIndex=0; witIndex<nbWitnesses; ++witIndex) {
        parseWitness<skip>(block, p);
    }
    if(!skip) {
        endWitnesses(p);
    }
}


template<bool skip>
static const uint8_t* parseTX(const Block *block, const uint8_t *&p) {
    auto txStart = p;
    auto txEnd = p;
    auto txWit = p;
    if(!skip)
        txWit = parseTX<true>(block, txEnd); // get txEnd, do nothing else

    uint8_t *txHash = 0;
    if(gNeedTXHash && !skip) {
        txHash = allocHash256();
        if (txWit > txStart) {
            sha256SegWitTwice(txHash, txStart, txWit - txStart - 6, txEnd - txWit - 4);
        } else {
            sha256Twice(txHash, txStart, txEnd - txStart);
        }
    }
    if(!skip)
        startTX(p, txHash, txEnd);

    SKIP(uint32_t, version, p);
    uint8_t dummy = *p;
    uint8_t flags = *(p+1);
    if (dummy == 0 && flags == 1) {
        p += 2;
    }
    uint64_t nbInputs = parseInputs<skip>(block, p, txHash);
    Chunk *txo = 0;
    size_t txoOffset = -1;
    const uint8_t *outputsStart = p;
    if(gNeedTXHash && gNeedEdge && !skip) {
        txo = Chunk::alloc();
        txoOffset = block->chunk->getOffset() + (p - block->chunk->getData());
        gTXOMap[txHash] = txo;
    }
    parseOutputs<skip, false>(p, txHash);
    if(txo) {
        size_t txoSize = p - outputsStart;
        txo->init(block->chunk->getMap(), txoSize, txoOffset);
        txo->getData(outputsStart);
    } else if (txHash) {
        freeHash256(txHash);
    }
    if (dummy == 0 && flags == 1) {
        txWit = p;
        for(uint64_t witIndex=0; witIndex<nbInputs; ++witIndex) {
            parseWitnesses<skip>(block, p);
        }
    }
    SKIP(uint32_t, lockTime, p);

    if(!skip)
        endTX(p);
    return txWit;
}


static void showParseProgress(const Block *block) {
    static double startTime = 0;
    static double lastStatTime = 0;
    static uint64_t offset = 0;
    offset += block->chunk->getSize();
    double now = usecs();
    double elapsed = now - lastStatTime;
    bool longEnough = (5*1000*1000<elapsed);
    bool closeEnough = ((gChainSize - offset)<80);
    if(unlikely(longEnough || closeEnough)) {
        if(0==startTime) {
            startTime = now;
        }
        double progress = offset/(double)gChainSize;
        double elasedSinceStart = 1e-6*(now - startTime);
        double speed = progress / elasedSinceStart;
        fprintf(stderr, "%8ld blocks, %6.2f%%, elapsed = %5.2fs, eta = %5.2fs, nUtxo: %lu\r",
             block->height, 100.0*progress,
             elasedSinceStart, (1.0/speed)-elasedSinceStart,
             gTXOMap.size());

        lastStatTime = now;
    }
}


static void parseBlock(const Block *block) {
    startBlock(block);
    size_t size = block->chunk->getSize();
    auto p = block->chunk->getData();
    showParseProgress(block);   // in every 5 seconds

    SKIP(uint32_t, version, p);
    SKIP(uint256_t, prevBlkHash, p);
    SKIP(uint256_t, blkMerkleRoot, p);
    SKIP(uint32_t, blkTime, p);
    SKIP(uint32_t, blkBits, p);
    SKIP(uint32_t, blkNonce, p);

    startTXs(p);
    LOAD_VARINT(nbTX, p);
    for(uint64_t txIndex=0; likely(txIndex<nbTX); ++txIndex) {
        parseTX<false>(block, p);
    }
    endTXs(p);

    // block->chunk->releaseData();
    endBlock(block);
}


static void parseLongestChain() {
    info("pass 4 -- full blockchain analysis ...");
    gCallback->startLC();
    auto blk = gNullBlock->next;
    start(blk, gMaxBlock);
    int int_last_map_fd = 0;

    while(likely(0!=blk)) {
        auto map = blk->chunk->getMap();
        int bytes_read = 0;
        if (int_last_map_fd != map->fd) {
            int_last_map_fd = map->fd;
            auto where = lseek64(map->fd, 0, SEEK_SET);
            if(where!=0) {
                sysErrFatal("failed to seek into block chain file %s", map->name.c_str());
            }
            while (true) {
                auto sz = read(map->fd, map->data+bytes_read, 64*1024*1024);
                if ((sz <= 0) && (errno != EINTR)) {
                    perror("map failed.");
                    errFatal("can't map block, size:%d, fd:%d", map->size, map->fd);
                } else if (sz > 0) {
                    bytes_read += sz;
                    if(bytes_read >= (signed)map->size) {
                        break;
                    }
                }
            }
        }
        parseBlock(blk);
        blk = blk->next;
    }
    gCallback->wrapup();
    info("pass 4 -- done.");
}


static void wireLongestChain() {
    info("pass 3 -- wire longest chain ...");
    auto block = gMaxBlock;
    while(1) {
        auto prev = block->prev;
        if(unlikely(0==prev)) {
            break;
        }
        prev->next = block;
        block = prev;
    }
    info("pass 3 -- done, maxHeight=%d", (int)gMaxHeight);
}


static void initCallback(int argc, char *argv[]) {
    const char *methodName = 0;
    if(0<argc) {
        methodName = argv[1];
    }
    if(0==methodName) {
        methodName = "";
    }
    if(0==methodName[0]) {
        methodName = "help";
    }
    gCallback = Callback::find(methodName);
    fprintf(stderr, "\n");

    info("starting command '%s'", gCallback->name());
    if(argv[1]) {
        auto i = 0;
        while('-'==argv[1][i]) {
            argv[1][i++] = 'x';
        }
    }
    auto ir = gCallback->init(argc, (const char **)argv);
    if(ir<0) {
        errFatal("callback init failed");
    }
    gNeedTXHash = gCallback->needTXHash();
    gNeedEdge = gCallback->needEdge();
}


static void findBlockParent(Block *b) {
    auto i = gBlockMap.find(b->prev_hash);
    if(unlikely(gBlockMap.end()==i)) {
        uint8_t bHash[2*kSHA256ByteSize + 1];
        toHex(bHash, b->hash);

        uint8_t pHash[2*kSHA256ByteSize + 1];
        toHex(pHash, b->prev_hash);

        warning("in block %s failed to locate parent block %s", bHash, pHash);
        return;
    }
    b->prev = i->second;
}


static void computeBlockHeight(Block  *block, size_t &lateLinks) {
    if(unlikely(gNullBlock==block)) {
        return;
    }
    auto b = block;
    while(b->height<0) {
        if(unlikely(0==b->prev)) {
            findBlockParent(b);
            ++lateLinks;
            if(0==b->prev) {
                warning("failed to locate parent block");
                return;
            }
        }
        b->prev->next = b;
        b = b->prev;
    }
    auto height = b->height;
    while(1) {
        b->height = height++;
        if(likely(gMaxHeight < b->height)) {
            gMaxHeight = b->height;
            gMaxBlock = b;
        }
        auto next = b->next;
        b->next = 0;
        if(block==b) {
            break;
        }
        b = next;
    }
}


static void computeBlockHeights() {
    size_t lateLinks = 0;
    info("pass 2 -- link all blocks ...");
    for(const auto &pair:gBlockMap) {
        computeBlockHeight(pair.second, lateLinks);
    }
    info("pass 2 -- done, did %d late links", (int)lateLinks);
}


static void getBlockHeader(size_t &size, Block *&prev, uint8_t *&hash, uint8_t *&prev_hash, size_t &earlyMissCnt, const uint8_t *p) {
    LOAD(uint32_t, magic, p);
    if(unlikely(gExpectedMagic != magic)) {
        hash = 0;
        prev_hash = 0;
        return;
    }
    LOAD(uint32_t, sz, p);
    size = sz;
    prev = 0;
    hash = allocHash256();
    sha256Twice(hash, p, gHeaderSize);

    prev_hash = allocHash256();
    memcpy(prev_hash, p + 4, kSHA256ByteSize);

    auto i = gBlockMap.find(prev_hash);
    if(likely(gBlockMap.end()!=i)) {
        prev = i->second;
    } else {
        ++earlyMissCnt;
    }
}


static void buildBlockHeaders() {
    info("pass 1 -- walk all blocks and build headers ...");
    size_t nbBlocks = 0;
    size_t baseOffset = 0;
    size_t earlyMissCnt = 0;
    size_t blockSize = 0;
    uint8_t *hash = 0;
    uint8_t *prev_hash = 0;
    uint8_t buf[8+gHeaderSize];
    Block *prevBlock = 0;
    int nbCache = 0;
    int nbData = 0;
    int nbWrite = 0;
    const auto sz = sizeof(buf);
    const auto startTime = usecs();
    for(const auto &map : mapVec) {
        startMap(0);
        size_t blockOffset = 8;
        while(1) {
            if (map.size < blockOffset + gHeaderSize)
                break;

            size_t nbRead;
            // if ((gChainSize - baseOffset) > 128*1024*1024 && blockMapCacheSize >= (nbBlocks+1)*sz) {
            if (blockMapCacheSize >= (nbBlocks+1+1)*sz) {
                nbRead = read(blockMapCacheFD, buf, sz);
                if(nbRead<(signed)sz) {
                    break;
                }
                nbCache++;
                auto where = lseek(map.fd, sz, SEEK_CUR);
                if(where<0) {
                    break;
                }
            } else {
                nbRead = read(map.fd, buf, sz);
                if(nbRead<(signed)sz) {
                    break;
                }
                nbData++;
                nbRead = write(blockMapCacheFD, buf, sz);
                if(nbRead<(signed)sz) {
                    break;
                }
                nbWrite++;
            }
            startBlock((uint8_t*)0);

            getBlockHeader(blockSize, prevBlock, hash, prev_hash, earlyMissCnt, buf);
            if(unlikely(0==hash)) {
                break;
            }
            auto where = lseek(map.fd, (blockSize + 8) - sz, SEEK_CUR);
            if(where<0) {
                break;
            }

            // real work
            auto block = Block::alloc();
            block->init(hash, prev_hash, &map, blockSize, prevBlock, blockOffset);
            gBlockMap[hash] = block;

            blockOffset += (8 + blockSize);
            endBlock((uint8_t*)0);
            ++nbBlocks;
        }
        // progress info
        auto now = usecs();
        auto elapsed = now - startTime;
        const auto oneMeg = 1024 * 1024;
        baseOffset += map.size;
        auto bytesPerSec = baseOffset / (elapsed*1e-6);
        auto bytesLeft = gChainSize - baseOffset;
        auto secsLeft = bytesLeft / bytesPerSec;
        fprintf(stderr, "%.2f%% (%.2f/%.2f Gigs) - %6d blocks - %.2f Megs/sec - ETA %.0f secs - ELAPSED %.0f secs (%d, %d, %d)\r",
                (100.0*baseOffset)/gChainSize, baseOffset/(1000.0*oneMeg), gChainSize/(1000.0*oneMeg),
                (int)nbBlocks, bytesPerSec*1e-6, secsLeft, elapsed*1e-6, nbData, nbCache, nbWrite);
        fflush(stderr);
        endMap(0);
    }
    if(0 == nbBlocks) {
        warning("found no blocks - giving up");
        exit(1);
    }
    char msg[128] = "";
    if(0 < earlyMissCnt) {
        sprintf(msg, ", %d early link misses", (int)earlyMissCnt);
    }
    auto elapsed = 1e-6*(usecs() - startTime);
    info("\npass 1 -- took %.0f secs, %6d blocks, %.2f Gigs, %.2f Megs/secs %s", elapsed,
        (int)nbBlocks, (gChainSize * 1e-9), (gChainSize * 1e-6) / elapsed, msg);
}


static void buildNullBlock() {
    gBlockMap[gNullHash.v] = gNullBlock = Block::alloc();
    gNullBlock->init(gNullHash.v, gNullHash.v, 0, 0, 0, 0);
    gNullBlock->height = 0;
}


static void initHashtables() {
    info("initializing hash tables");
    gTXOMap.setEmptyKey(empty);
    gTXOMap.setDeleteKey(hash256_deleted);
    gBlockMap.setEmptyKey(empty);

    gChainSize = 0;
    for(const auto &map : mapVec) {
        gChainSize += map.size;
    }

    auto txPerBytes = (13141592.6 / 26645195995.0);
    auto nbTxEstimate = (size_t)(1.1 * txPerBytes * gChainSize);
    gTXOMap.resize(nbTxEstimate);

    auto blocksPerBytes = (331284.0 / 26645195995.0);
    auto nbBlockEstimate = (size_t)(1.1 * blocksPerBytes * gChainSize);
    gBlockMap.resize(nbBlockEstimate);

    info("estimated number of blocks = %.2fK", 1e-3*nbBlockEstimate);
    info("estimated number of transactions = %.2fM", 1e-6*nbTxEstimate);
}


static void makeBlockMaps() {
    const char *home = getenv("HOME");
    if(0==home) {
        warning("could not getenv(\"HOME\"), using \".\" instead.");
        home = ".";
    }
    std::string homeDir(home);
    std::string blockDir = homeDir + gCoinDirName + std::string("blocks");
    struct stat statBuf;
    auto r = stat(blockDir.c_str(), &statBuf);
    auto oldStyle = (r<0 || !S_ISDIR(statBuf.st_mode));
    int blkDatId = (oldStyle ? 1 : 0);
    auto fmt = oldStyle ? "blk%04d.dat" : "blocks/blk%05d.dat";
    blockMapCacheFileName = homeDir + gCoinDirName + std::string("blocks_parser_cache.dat");
    blockMapCacheFD = open(blockMapCacheFileName.c_str(), O_RDWR|O_CREAT, S_IREAD|S_IWRITE);

    while(1) {
        // if(10 < blkDatId) {
        //   break;
        // }
        char buf[64];
        sprintf(buf, fmt, blkDatId++);
        auto blockMapFileName = homeDir + gCoinDirName + std::string(buf);
        auto blockMapFD = open(blockMapFileName.c_str(), O_RDONLY);
        if(blockMapFD<0) {
            if(1<blkDatId) {
                break;
            }
            sysErrFatal("failed to open block chain file %s", blockMapFileName.c_str());
        }
        struct stat statBuf;
        int st0 = fstat(blockMapFD, &statBuf);
        if(st0<0) {
            sysErrFatal("failed to fstat block chain file %s", blockMapFileName.c_str());
        }
        auto mapSize = statBuf.st_size;
        auto st1 = posix_fadvise(blockMapFD, 0, mapSize, POSIX_FADV_NOREUSE);
        if(st1<0) {
            warning("failed to posix_fadvise on block chain file %s", blockMapFileName.c_str());
        }
        auto st2 = fstat(blockMapCacheFD, &statBuf);
        if(st2<0) {
            sysErrFatal("failed to fstat block chain file %s", blockMapCacheFileName.c_str());
        }
        blockMapCacheSize = statBuf.st_size;
        Map map;
        map.size = mapSize;
        map.fd = blockMapFD;
        map.data = map_data_cache;
        map.name = blockMapFileName;
        mapVec.push_back(map);
    }
}


static void cleanMaps() {
    auto r = close(blockMapCacheFD);
    if(r<0) {
        sysErr("failed to close block chain file %s", blockMapCacheFileName.c_str());
    }
    for(const auto &map : mapVec) {
        r = close(map.fd);
        if(r<0) {
            sysErr("failed to close block chain file %s", map.name.c_str());
        }
    }
}


int main(int argc, char *argv[]) {
    auto start = usecs();
    initCallback(argc, argv);
    makeBlockMaps();            // open files
    initHashtables();
    buildNullBlock();
    buildBlockHeaders();        // 1. load blocks
    computeBlockHeights();      // 2
    wireLongestChain();         // 3
    parseLongestChain();        // 4. parse blocks
    cleanMaps();
    auto elapsed = (usecs() - start)*1e-6;
    info("all done in %.2f seconds\n", elapsed);
    return 0;
}
