#ifndef __CALLBACK_H__
    #define __CALLBACK_H__

    struct Block;
    #include <vector>
    #include <common.h>
    #include <option.h>

    // Derive from this if you want to add a new command
    struct Callback
    {
        // Housekeeping
        Callback();
        typedef optparse::OptionParser Parser;
        static void showAllHelps(bool longHelp);
        static Callback *find(const char *name, bool printList=false);

        // Naming, option parsing, construction, etc ...

        virtual const char *name() const = 0; // Main name for callback
        virtual const Parser *optionParser() const = 0; // Option parser object for callback
        virtual void aliases(std::vector<const char *> &v) const {}  // Alternate names for callback

        // Called after callback construction, with command line arguments
        virtual int init(int argc, const char *argv[]){return 0;}

        // Overload if you need parser to compute TX hashes
        virtual bool needTXHash() const {return false;}
        // Overload if you need parser to compute Edge
        virtual bool needEdge() const {return true;}

        // Callback for first, shallow parse -- all blocks are seen, including orphaned ones but aren't parsed
        virtual void startMap(const uint8_t *p){}   // a blockchain file is mapped into memory
        virtual void endMap(const uint8_t *p){}     // a blockchain file is unmapped from memory
        virtual void startBlock(const uint8_t *p){} // a block is encountered during first pass
        virtual void endBlock(const uint8_t *p){}   // an end of block is encountered during first pass

        // Callback for second, deep parse -- only valid blocks are seen, and are parsed in details
        virtual void start(const Block *s, const Block *e){} // the second parse of the full chain starts
        virtual void startBlock(const Block *b,
                                uint64_t chainSize){}  // a new block is encountered
        virtual void endBlock(const Block *b){}        // an end of block is encountered

        virtual void startLC(){}                       // longest chain parse starts
        virtual void wrapup(){}                        // the whole chain has been parsed

        virtual void startTXs(const uint8_t *p){}      // start list of TX is encountered
        virtual void endTXs(const uint8_t *p){}        // end list of TX is encountered

        virtual void startTX(const uint8_t *p,
                             const uint8_t *hash,
                             const uint8_t *txEnd=0){} // a new TX is encountered
        virtual void endTX(const uint8_t *p){}         // an end of TX is encountered

        virtual void startInputs(const uint8_t *p){}   // the start of a TX's input array is encountered
        virtual void endInputs(const uint8_t *p){}     // the end of a TX's input array is encountered

        virtual void startInput(const uint8_t *p){}    // a TX input is encountered
        // exactly like startInput, but with a much richer context
        virtual void edge(
                          uint64_t value,            // Number of satoshis coming in on this input from upstream tx
                    const uint8_t *upTXHash,         // sha256 of upstream tx
                          uint64_t outputIndex,      // Index of output in upstream tx
                          // Raw script (challenge to spender) carried by output in upstream tx
                    const uint8_t *outputScript,
                          uint64_t outputScriptSize, // Byte size of script carried by output in upstream tx
                    const uint8_t *downTXHash,       // sha256 of current (downstream) tx
                          uint64_t inputIndex,       // Index of input in downstream tx
                          // Raw script (answer to challenge) carried by input in downstream tx
                    const uint8_t *inputScript,
                          uint64_t inputScriptSize   // Byte size of script carried by input in downstream tx
        ) {}
        virtual inline void endInput(const uint8_t *pend, // Pointer to TX output raw data
                                     const uint8_t *upTXHash,
                                     uint64_t      outputIndex,
                                     const uint8_t *downTXHash,
                                     uint64_t      inputIndex,
                                     const uint8_t *inputScript,
                                     uint64_t      inputScriptSize
                                     ) {}

        virtual void startWitnesses(const uint8_t *p){}   // the start of a TX's input array is encountered
        virtual void endWitnesses(const uint8_t *p){}     // the end of a TX's input array is encountered
        virtual void startWitness(const uint8_t *p){}    // a TX input is encountered

        virtual void startOutputs(const uint8_t *p){} // the start of a TX's output array is encountered
        virtual void endOutputs(const uint8_t *p){}   // the end of a TX's output array is encountered

        virtual void startOutput(const uint8_t *p){}  // a TX output is encountered
        virtual void endOutput(            // an output has been fully parsed
            const uint8_t *p,              // Pointer to TX output raw data
            uint64_t      value,           // Number of satoshis on this output
            const uint8_t *txHash,         // sha256 of the current tx
            uint64_t      outputIndex,     // Index of this output in the current tx
            const uint8_t *outputScript,   // Raw script (challenge to would-be spender) carried by this output
            uint64_t      outputScriptSize // Byte size of raw script
        ) {}
    };

#endif // __CALLBACK_H__
