#include "coin.h"
//#include "util.h"
//#include "amount.h"

#include <openssl/rand.h>
#include <sstream>
#include "openssl_context.h"
#include "../bitcoin/uint256.h"
#include "../bitcoin/arith_uint256.h"
#include "../bitcoin/hash.h"
//#include "../bitcoin/crypto/hmac_sha256.h"
#include "../bitcoin/crypto/hmac_sha512.h"
#include "../bitcoin/crypto/sha256.h"
#include "../bitcoin/crypto/sha512.h"


namespace sigma {

std::ostream& operator<<(std::ostream& stream, CoinDenomination denomination) {
    int64_t denom_value;
    DenominationToInteger(denomination, denom_value);
    stream << denom_value;
    return stream;
}

bool DenominationToInteger(CoinDenomination denom, int64_t& denom_out){
    switch (denom) {
        default:
            throw std::runtime_error("Invalid denomination value, unable to convert to integer");
        case CoinDenomination::SIGMA_DENOM_0_05:
            denom_out = 5 * CENT;
            break;
        case CoinDenomination::SIGMA_DENOM_0_1:
            denom_out = 10 * CENT;
            break;
        case CoinDenomination::SIGMA_DENOM_0_5:
            denom_out = 50 * CENT;
            break;
        case CoinDenomination::SIGMA_DENOM_1:
            denom_out = COIN;
            break;
        case CoinDenomination::SIGMA_DENOM_10:
            denom_out = 10 * COIN;
            break;
        case CoinDenomination::SIGMA_DENOM_25:
            denom_out = 25 * COIN;
            break;
        case CoinDenomination::SIGMA_DENOM_100:
            denom_out = 100 * COIN;
            break;
    }
return true;
}

bool IntegerToDenomination(int64_t value, CoinDenomination& denom_out) {
    switch (value) {
        default:
            throw std::runtime_error("Invalid denomination value, unable to convert to enum");
        case 5 * CENT:
            denom_out = CoinDenomination::SIGMA_DENOM_0_05;
            break;
        case 10 * CENT:
            denom_out = CoinDenomination::SIGMA_DENOM_0_1;
            break;
        case 50 * CENT:
            denom_out = CoinDenomination::SIGMA_DENOM_0_5;
            break;
        case 1 * COIN:
            denom_out = CoinDenomination::SIGMA_DENOM_1;
            break;
        case 10 * COIN:
            denom_out = CoinDenomination::SIGMA_DENOM_10;
            break;
        case 25 * COIN:
            denom_out = CoinDenomination::SIGMA_DENOM_25;
            break;
        case 100 * COIN:
            denom_out = CoinDenomination::SIGMA_DENOM_100;
            break;
    }
return true;
}

//class PublicCoin
PublicCoin::PublicCoin()
    : denomination(CoinDenomination::SIGMA_DENOM_1)
{

}

PublicCoin::PublicCoin(const GroupElement& coin, const CoinDenomination d)
    : value(coin)
    , denomination(d)
{
}

const GroupElement& PublicCoin::getValue() const{
    return this->value;
}

CoinDenomination PublicCoin::getDenomination() const {
    return denomination;
}

bool PublicCoin::operator==(const PublicCoin& other) const{
    return (*this).value == other.value;
}

bool PublicCoin::operator!=(const PublicCoin& other) const{
    return (*this).value != other.value;
}

bool PublicCoin::validate() const{
    return this->value.isMember() && !this->value.isInfinity();
}

size_t PublicCoin::GetSerializeSize(int nType, int nVersion) const{
    return value.memoryRequired() + sizeof(int);
}

//class PrivateCoin
PrivateCoin::PrivateCoin(const Params* p, CoinDenomination denomination, int version)
    : params(p)
{
        this->version = version;
        this->mintCoin(denomination);
}

//class PrivateCoin
PrivateCoin::PrivateCoin(const Params* p, CoinDenomination denomination, BIP44MintData data, int version)
    : params(p)
{
        this->version = version;
        if(!this->mintCoin(denomination, data))
            throw std::invalid_argument("seed is invalid.");
}

const Params * PrivateCoin::getParams() const {
    return this->params;
}

const PublicCoin& PrivateCoin::getPublicCoin() const{
    return this->publicCoin;
}

const Scalar& PrivateCoin::getSerialNumber() const{
    return this->serialNumber;
}

const Scalar& PrivateCoin::getRandomness() const{
    return this->randomness;
}

const unsigned char* PrivateCoin::getEcdsaSeckey() const {
     return this->ecdsaSeckey;
}

void PrivateCoin::setEcdsaSeckey(const std::vector<unsigned char> &seckey) {
    if (seckey.size() == sizeof(ecdsaSeckey))
        std::copy(seckey.cbegin(), seckey.cend(), &ecdsaSeckey[0]);
    else
        throw std::invalid_argument("EcdsaSeckey size does not match.");
}

void PrivateCoin::setEcdsaSeckey(uint256 &seckey) {
    if (seckey.size() == sizeof(ecdsaSeckey))
        std::copy(seckey.begin(), seckey.end(), &ecdsaSeckey[0]);
    else
        throw std::invalid_argument("EcdsaSeckey size does not match.");
}

unsigned int PrivateCoin::getVersion() const {
    return this->version;
}

void PrivateCoin::setPublicCoin(const PublicCoin& p) {
    publicCoin = p;
}

void PrivateCoin::setRandomness(const Scalar& n) {
    randomness = n;
}

void PrivateCoin::setSerialNumber(const Scalar& n) {
    serialNumber = n;
}

void PrivateCoin::setVersion(unsigned int nVersion){
    version = nVersion;
}

void PrivateCoin::mintCoin(const CoinDenomination denomination){
    // Create a key pair
    secp256k1_pubkey pubkey;
    do {
        if (RAND_bytes(this->ecdsaSeckey, sizeof(this->ecdsaSeckey)) != 1) {
            throw std::runtime_error("Unable to generate randomness");
        }
    } while (!secp256k1_ec_pubkey_create(
        OpenSSLContext::get_context(), &pubkey, this->ecdsaSeckey));

    // Hash the public key in the group to obtain a serial number
    serialNumber = serialNumberFromSerializedPublicKey(
        OpenSSLContext::get_context(), &pubkey);

    randomness.randomize();
    GroupElement commit = SigmaPrimitives<Scalar, GroupElement>::commit(
            params->get_g(), serialNumber, params->get_h0(), randomness);
    publicCoin = PublicCoin(commit, denomination);
}

bool PrivateCoin::mintCoin(const CoinDenomination denomination, const BIP44MintData data){
    // See https://github.com/zcoinofficial/zcoin/pull/392 for specification
    // HMAC-SHA512(SHA256(index),key)
    unsigned char countHash[CSHA256().OUTPUT_SIZE];
    std::vector<unsigned char> result(CSHA512().OUTPUT_SIZE);

    std::string nCountStr = to_string(data.getIndex());
    CSHA256().Write(reinterpret_cast<const unsigned char*>(nCountStr.c_str()), nCountStr.size()).Finalize(countHash);

    CHMAC_SHA512(countHash, CSHA256().OUTPUT_SIZE).Write(data.getKeyData(), data.size()).Finalize(&result[0]);

    uint512 seed = uint512(result);

    // Hash top 256 bits of seed for ECDSA key
    uint256 nSeedPrivKey = seed.trim256();
    nSeedPrivKey = Hash(nSeedPrivKey.begin(), nSeedPrivKey.end());
    this->setEcdsaSeckey(nSeedPrivKey);

    // Create a key pair
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(OpenSSLContext::get_context(), &pubkey, this->ecdsaSeckey)){
        return false;
    }
    // Hash the public key in the group to obtain a serial number
    serialNumber = serialNumberFromSerializedPublicKey(
        OpenSSLContext::get_context(), &pubkey);

    //hash randomness seed with Bottom 256 bits of seed
    uint256 nSeedRandomness = ArithToUint512(UintToArith512(seed) >> 256).trim256();
    randomness.memberFromSeed(nSeedRandomness.begin());

    // Generate a Pedersen commitment to the serial number
    GroupElement commit = SigmaPrimitives<Scalar, GroupElement>::commit(
             params->get_g(), serialNumber, params->get_h0(), randomness);
    publicCoin = PublicCoin(commit, denomination);

    return true;
}

Scalar PrivateCoin::serialNumberFromSerializedPublicKey(
        const secp256k1_context *context,
        secp256k1_pubkey *pubkey) {
    std::vector<unsigned char> pubkey_hash(32, 0);

    static const unsigned char one[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };

    // We use secp256k1_ecdh instead of secp256k1_serialize_pubkey to avoid a timing channel.
    if (1 != secp256k1_ecdh(context, pubkey_hash.data(), pubkey, &one[0],NULL, NULL)) {
        throw std::runtime_error("Unable to compute public key hash with secp256k1_ecdh.");
    }

	std::string zpts("PUBLICKEY_TO_SERIALNUMBER");
	std::vector<unsigned char> pre(zpts.begin(), zpts.end());
    std::copy(pubkey_hash.begin(), pubkey_hash.end(), std::back_inserter(pre));

	unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(pre.data(), pre.size()).Finalize(hash);

    // Use 32 bytes of hash as coin serial.
    return Scalar(hash);
}

} // namespace sigma

namespace std {

string to_string(::sigma::CoinDenomination denom)
{
    switch (denom) {
    case ::sigma::CoinDenomination::SIGMA_DENOM_0_05:
        return "0.05";
    case ::sigma::CoinDenomination::SIGMA_DENOM_0_1:
        return "0.1";
    case ::sigma::CoinDenomination::SIGMA_DENOM_0_5:
        return "0.5";
    case ::sigma::CoinDenomination::SIGMA_DENOM_1:
        return "1";
    case ::sigma::CoinDenomination::SIGMA_DENOM_10:
        return "10";
    case ::sigma::CoinDenomination::SIGMA_DENOM_25:
        return "25";
    case ::sigma::CoinDenomination::SIGMA_DENOM_100:
        return "100";
    default:
        throw invalid_argument("the specified denomination is not valid");
    }
}

} // namespace std
