#include "../src/coin.h"
#include "../src/params.h"

#define BOOST_TEST_MAIN
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(sigma_coin_tests)

BOOST_AUTO_TEST_CASE(pubcoin_validate)
{
    auto params = sigma::Params::get_default();

    sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    auto& pubcoin = privcoin.getPublicCoin();

    BOOST_CHECK(pubcoin.validate());
}

BOOST_AUTO_TEST_CASE(getter_setter_priv)
{
    auto params = sigma::Params::get_default();

    sigma::PrivateCoin privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);
    sigma::PrivateCoin new_privcoin(params, sigma::CoinDenomination::SIGMA_DENOM_1);

    BOOST_CHECK(privcoin.getPublicCoin() != new_privcoin.getPublicCoin());
    BOOST_CHECK(privcoin.getSerialNumber() != new_privcoin.getSerialNumber());
    BOOST_CHECK(privcoin.getRandomness() != new_privcoin.getRandomness());
    BOOST_CHECK(privcoin.getVersion() == new_privcoin.getVersion());

    new_privcoin.setPublicCoin(privcoin.getPublicCoin());
    new_privcoin.setRandomness(privcoin.getRandomness());
    new_privcoin.setSerialNumber(privcoin.getSerialNumber());
    new_privcoin.setVersion(2);

    BOOST_CHECK(privcoin.getPublicCoin() == new_privcoin.getPublicCoin());
    BOOST_CHECK(privcoin.getSerialNumber() == new_privcoin.getSerialNumber());
    BOOST_CHECK(privcoin.getRandomness() == new_privcoin.getRandomness());
    BOOST_CHECK(new_privcoin.getVersion() == 2);
}

BOOST_AUTO_TEST_SUITE_END()
