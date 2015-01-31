
// g++ -m64 -O6 -DWANT_DENSE -I. -lcrypto vanitygen.cpp util.cpp sha256.cpp rmd160.cpp opcodes.cpp -o vanitygen

#include <stdio.h>
#include <string.h>
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


#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>


#if !defined(O_DIRECT)
#   define O_DIRECT 0
#endif

struct Map
{
    int fd;
    uint64_t size;
    const uint8_t *p;
    std::string name;
};

typedef GoogMap<Hash160, uint128_t, Hash160Hasher, Hash160Equal>::Map::iterator Iterator;
typedef GoogMap<Hash160, uint128_t, Hash160Hasher, Hash160Equal>::Map AddrMap;


static bool gNeedTXHash;
static Callback *gCallback;

static const Map *gCurMap;
static std::vector<Map> mapVec;
static Iterator g_curr_i_txmap;
static AddrMap gAddrMap;
static uint8_t emptyKey[kSHA256ByteSize] = { 0x52 };

static uint8_t hash256_deleted[kSHA256ByteSize] = { 0x00 };

static uint64_t gChainSize;
static uint64_t gMaxHeight;
static uint256_t gNullHash;

const char *vg_b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int
vg_set_privkey(const BIGNUM *bnpriv, EC_KEY *pkey)
{
	const EC_GROUP *pgroup;
	EC_POINT *ppnt;
	int res;

	pgroup = EC_KEY_get0_group(pkey);
	ppnt = EC_POINT_new(pgroup);

	res = (ppnt &&
	       EC_KEY_set_private_key(pkey, bnpriv) &&
	       EC_POINT_mul(pgroup, ppnt, bnpriv, NULL, NULL, NULL) &&
	       EC_KEY_set_public_key(pkey, ppnt));

	if (ppnt)
		EC_POINT_free(ppnt);

	if (!res)
		return 0;

	assert(EC_KEY_check_key(pkey));
	return 1;
}


void
vg_b58_encode_check(void *buf, size_t len, char *result)
{
	unsigned char hash1[32];
	unsigned char hash2[32];

	int d, p;

	BN_CTX *bnctx;
	BIGNUM *bn, *bndiv, *bntmp;
	BIGNUM bna, bnb, bnbase, bnrem;
	unsigned char *binres;
	int brlen, zpfx;

	bnctx = BN_CTX_new();
	BN_init(&bna);
	BN_init(&bnb);
	BN_init(&bnbase);
	BN_init(&bnrem);
	BN_set_word(&bnbase, 58);

	bn = &bna;
	bndiv = &bnb;

	brlen = (2 * len) + 4;
	binres = (unsigned char*) malloc(brlen);
	memcpy(binres, buf, len);

	SHA256(binres, len, hash1);
	SHA256(hash1, sizeof(hash1), hash2);
	memcpy(&binres[len], hash2, 4);

	BN_bin2bn(binres, len + 4, bn);

	for (zpfx = 0; zpfx < (len + 4) && binres[zpfx] == 0; zpfx++);

	p = brlen;
	while (!BN_is_zero(bn)) {
		BN_div(bndiv, &bnrem, bn, &bnbase, bnctx);
		bntmp = bn;
		bn = bndiv;
		bndiv = bntmp;
		d = BN_get_word(&bnrem);
		binres[--p] = vg_b58_alphabet[d];
	}

	while (zpfx--) {
		binres[--p] = vg_b58_alphabet[0];
	}

	memcpy(result, &binres[p], brlen - p);
	result[brlen - p] = '\0';

	free(binres);
	BN_clear_free(&bna);
	BN_clear_free(&bnb);
	BN_clear_free(&bnbase);
	BN_clear_free(&bnrem);
	BN_CTX_free(bnctx);
}



void
vg_encode_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
		  int addrtype, char *result)
{
	unsigned char eckey_buf[128], *pend;
	unsigned char binres[21] = {0,};
	unsigned char hash1[32];

	pend = eckey_buf;

	EC_POINT_point2oct(pgroup,
			   ppoint,
			   POINT_CONVERSION_UNCOMPRESSED,
			   eckey_buf,
			   sizeof(eckey_buf),
			   NULL);
	pend = eckey_buf + 0x41;
	binres[0] = addrtype;
	SHA256(eckey_buf, pend - eckey_buf, hash1);
	RIPEMD160(hash1, sizeof(hash1), &binres[1]);

    // hash160ToAddr((uint8_t*)result, (const uint8_t*)binres);
	vg_b58_encode_check(binres, sizeof(binres), result);
}

void
vg_encode_privkey(const EC_KEY *pkey, int addrtype, char *result)
{
	unsigned char eckey_buf[128];
	const BIGNUM *bn;
	int nbytes;

	bn = EC_KEY_get0_private_key(pkey);

	eckey_buf[0] = addrtype;
	nbytes = BN_num_bytes(bn);
	assert(nbytes <= 32);
	if (nbytes < 32)
		memset(eckey_buf + 1, 0, 32 - nbytes);
	BN_bn2bin(bn, &eckey_buf[33 - nbytes]);

	vg_b58_encode_check(eckey_buf, 33, result);
}

void
vg_encode_pubkey_hash160(const EC_POINT *ppoint, const EC_GROUP *pgroup,
                         unsigned char *binres)
{
	unsigned char eckey_buf[128], *pend;

	unsigned char hash1[32];

	pend = eckey_buf;

	EC_POINT_point2oct(pgroup,
			   ppoint,
			   POINT_CONVERSION_UNCOMPRESSED,
			   eckey_buf,
			   sizeof(eckey_buf),
			   NULL);
	pend = eckey_buf + 0x41;

	SHA256(eckey_buf, pend - eckey_buf, hash1);
	RIPEMD160(hash1, sizeof(hash1), binres);
}


int test_phrase(EC_KEY *pkey){

  char ecprot[128];
  char pbuf[1024];
  const char *passphrase = "hello";

  int privtype, addrtype;
  int opt;
  int res;

  if (passphrase) {
    unsigned char *pend = (unsigned char *) pbuf;
    addrtype = 0;
    privtype = 128;

    // BIGNUM bnpriv;
    // BN_init(&bnpriv);

    unsigned char ecpriv[32];

    // SHA256((const unsigned char*)passphrase, strlen(passphrase), ecpriv);
    // BN_bin2bn(ecpriv, 32, &bnpriv);


    EC_KEY_generate_key(pkey);


    // vg_set_privkey(&bnpriv, pkey);

    // BN_clear_free(&bnpriv);


    // res = i2o_ECPublicKey(pkey, &pend);
    // printf("Pubkey : ");
    // showHex((uint8_t*)pbuf, res, false);

    // vg_encode_address(EC_KEY_get0_public_key(pkey),
    //                   EC_KEY_get0_group(pkey),
    //                   addrtype, ecprot);

    // printf("Phrase: %s\n", passphrase);
    // printf("Address: %s\n", ecprot);

    /* printf("Privkey: "); */
    /* dumpbn(EC_KEY_get0_private_key(pkey)); */


    unsigned char hash160[20] = {0,};
    vg_encode_pubkey_hash160(EC_KEY_get0_public_key(pkey),
                             EC_KEY_get0_group(pkey),
                             hash160);

    Iterator i = gAddrMap.find(hash160);

    if(i != gAddrMap.end()){
      vg_encode_privkey(pkey, privtype, ecprot);

      printf("%s: %s\n", passphrase, ecprot);

      showHex(i->first, kRIPEMD160ByteSize, false);
      printf("\n");

      uint8_t address[128];
      hash160ToAddr(address, (const uint8_t*)hash160);
      printf("%s : %s\n", address, pr128(i->second).c_str());
    }


  }

  return 0;
}






int main()
{

  gAddrMap.setEmptyKey(emptyKey);

  FILE* fp_in = fopen("balance.data", "r");
  // months.unserialize(StringToIntSerializer(), fp_in);
  // fseek(fp_in, 20, 0);
  size_t getline_n = 256;
  char *getline_buf = (char *)malloc(getline_n);

  while(1) {

    // Read the value.

    size_t size = getline(&getline_buf, &getline_n, fp_in);

    if ((int)size < 0){
      break;
    }

    getline_buf[size-1] = 0;

    char* balance_str = strtok (getline_buf, "\t");
    uint128_t balance = 0;
    for(int i=0; i<size && (*balance_str) != '\0'; i++, balance_str++)
      {
        balance = balance*10 + ((*balance_str) - '0');
      }

    char* address = strtok (NULL, "\t");
    uint160_t pubKeyHash;

    if (true != addrToHash160(pubKeyHash.v, (const uint8_t*)address, false, false))
      break;

    uint8_t * hash160 = allocHash160();
    memcpy(hash160, pubKeyHash.v, kRIPEMD160ByteSize);
    gAddrMap[hash160] = balance;
  }

  fclose(fp_in);


  FILE* fp_phrase = fopen("phrase.data", "r");


  static double lastStatTime = 0;
  uint64_t n_phrase = 0;

  EC_KEY* pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
  EC_KEY_generate_key(pkey);
  while(1) {
    n_phrase++;
    double now = usecs();
    double elapsed = now - lastStatTime;
    bool longEnough = (1*1000*1000 < elapsed);
    if(unlikely(longEnough)) {

      printf("%d\n", n_phrase);

      lastStatTime = now;
    }

    // size_t size = getline(&getline_buf, &getline_n, fp_phrase);
    // if ((int)size < 0) break;
    // getline_buf[size-1] = 0;

    test_phrase(pkey);

  }
  free(getline_buf);
  fclose(fp_phrase);

  EC_KEY_free(pkey);

  // auto e = gAddrMap.end();
  // auto i = gAddrMap.begin();
  // while(i!=e) {
  //   printf("== ");
  //   showHex(i->first, kRIPEMD160ByteSize, false);
  //   printf(": %s\n",pr128(i->second).c_str());

  //   ++i;
  // }



}
