#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <libdevcore/Common.h>
#include <libdevcrypto/AES.h>
#include <libdevcrypto/Common.h>
#include <libdevcrypto/Hash.h>
// #include <openssl/ec.h>  // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new,
// EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free #include <openssl/ecdsa.h>  // for
// ECDSA_do_sign, ECDSA_do_verify #include <openssl/obj_mac.h> #include <stdio.h>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>

using namespace std;
using namespace std::chrono;
using namespace dev;
using namespace boost;

int main()
{
    auto version = string("");
    cout << "Testing encrypt/decrypt for DXCT" << version << " ..." << endl;

#ifdef FISCO_GM
    version = " for GM";
    // for (int i = 0; i < 5; i++)
    // {
    //     cout << endl;

    //     cout << "Testing SM4 PKCS#7 mode encrypt" << version << " ..." << endl;
    //     auto key = fromHex(toHex(dev::Secret::random().ref()));
    //     cout << "key = " << toHex(key) << endl;


    //     auto data = fromHex(toHex(dev::Secret::random().ref()));

    //     cout << "data = " << toHex(data) << endl;

    //     auto encryptedData = bytes();

    //     encryptedData = dev::aesCBCEncrypt(&data, &key);

    //     cout << " SM4 PKCS#7 encryptedData = " << toHex(encryptedData) << endl;

    //     auto decryptedData = bytes();

    //     decryptedData = dev::aesCBCDecrypt(&encryptedData, &key);
    //     cout << "SM4 PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    // }

    // for (int i = 0; i < 5; i++)
    // {
    //     cout << endl;
    //     cout << "Testing SM2 sign" << version << " ..." << endl;
    //     KeyPair keyPair = KeyPair::create();
    //     cout << "SM2 [keyPair.pub()] = " << keyPair.pub() << endl;
    //     cout << "SM2 [keyPair.secret()] = " << keyPair.secret() << endl;
    //     cout << "SM2 [keyPair.secret().ref()] = " << toHex(keyPair.secret().ref()) << endl;
    //     // cout << "SM2 [keyPair.secret().ref() to pub] = " << toPublic(keyPair.secret().ref()) << endl;
    //     // SM3
    //     h256 hash(dev::Secret::random().ref());
    //     cout << "SM2 messegae = " << hash << endl;

    //     Signature signature;
    //     signature = sign(keyPair.secret(), hash);
    //     h512 v(keyPair.pub());
    //     cout << "SM2 verify signature with pub = " << dev::Signature(signature) << endl;
    //     cout << "SM2 verfiy result = " << verify(v, signature, hash) << endl;
    // }

    // for (int i = 0; i < 5; i++)
    // {
    //     // h256 hash(dev::Secret::random().ref());
    //     auto string = dev::Secret::random().ref();
    //     cout << "messgae = " << toHex(string) << endl;
    //     auto hash = dev::sha3(string);
    //     cout << "sm3 = " << hash << endl;
    // }

    // {
    //     cout << endl;
    //     cout << "Testing SM2 sign" << version << " ..." << endl;
    //     bytes bytesKey =
    //         fromHex("4B522E7E65EEA7CC2427239AD403E5FAE654810A685173A91334A33E6E7DCFA8");
    //     Secret secret(bytesKey);
    //     cout << "secretKey = " << toHex(secret.ref()) << endl;
    //     KeyPair keyPair(secret);
    //     cout << "SM2 [keyPair.pub()] = " << keyPair.pub() << endl;
    //     // SM3
    //     h256 hash(fromHex("2DAEF60E7A0B8F5E024C81CD2AB3109F2B4F155CF83ADEB2AE5532F74A157FDF"));

    //     Signature signature;
    //     signature = sign(keyPair.secret(), hash);
    //     h512 v(keyPair.pub());
    //     cout << "SM2 verify signature with pub = " << dev::Signature(signature) << endl;
    //     cout << "SM2 verfiy result = " << verify(v, signature, hash) << endl;
    // }

    // {
    //     cout << endl;

    //     cout << "Testing SM4 PKCS#7 mode decrypt" << version << " ..." << endl;
    //     auto key = fromHex("69C6A82B230934545747DAF2D84C9939");  // GM
    //     auto iv = fromHex("00000000000000000000000000000000");  // GM

    //     cout << "key = " << toHex(key) << endl;
    //     cout << "iv = " << toHex(iv) << endl;

    //     // auto iv = key;
    //     // cout << "iv = " << toHex(iv) << endl;
    //         //     auto encryptedData = bytes();

    //     // auto data = fromHex(
    //     //     "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");  // GM

    //     // cout << "data = " << toHex(data) << endl;

    //     // auto encryptedData = dev::aesCBCEncrypt(&data, &key);
    //     auto encryptedData = fromHex("DBD6A059EFAFCB2878863C342E1BFF4F8B2BE7922E187988517F3B0D8F66F5275DA6193501198DFB31EFCD370E7074F508A19A99D6CE4291D71B6526AC23F101"); 

    //     cout << " SM4 PKCS#7 encryptedData = " << toHex(encryptedData) << endl;

    //     auto decryptedData = bytes();

    //     decryptedData = dev::aesCBCDecrypt(&encryptedData, &key, &iv);
    //     cout << "SM4 PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    // }

    {
        cout << endl;
        cout << "Testing SM2 key pair generate" << version << " ..." << endl;
        bytes bytesKey =
            fromHex("4B522E7E65EEA7CC2427239AD403E5FAE654810A685173A91334A33E6E7DCFA8");  // GM

        Secret secret(bytesKey);
        cout << "secretKey = " << toHex(secret.ref()) << endl;
        KeyPair keyPair(secret);
        cout << "SM2 [keyPair.pub()] = " << keyPair.pub() << endl;
    }
    

    {
        cout << endl;
        cout << "Testing SM2 sign" << version << " ..." << endl;
        bytes bytesKey =
            fromHex("D96C222D8602B287973E2ACA7E3FEDADFD0BD67F2914D3E16F46FAB8A8506F2B");
        Secret secret(bytesKey);
        KeyPair keyPair(secret);
        // SM3
        h256 hash(fromHex("44DB476208775A0E5DBD7C00D08833A7083E232DFA95788E2EC7CC231772C23A"));
        cout << "SM2 [hash ] = " << toHex(hash) << endl;


        Signature signature;
        signature = sign(keyPair.secret(), hash);
        h512 v(keyPair.pub());
        cout << "secretKey = " << toHex(secret.ref()) << endl;
        cout << "SM2 [keyPair.pub()] = " << keyPair.pub() << endl;
        cout << "SM2 verify signature with pub = " << dev::Signature(signature) << endl;
        cout << "SM2 verfiy result = " << verify(v, signature, hash) << endl;
    }
    

    {
        cout << endl;
        cout << "Testing SM2 verify" << version << " ..." << endl;
        bytes bytesKey =
            fromHex("D96C222D8602B287973E2ACA7E3FEDADFD0BD67F2914D3E16F46FAB8A8506F2B");
        Secret secret(bytesKey);
        cout << "secretKey = " << toHex(secret.ref()) << endl;
        KeyPair keyPair(secret);
        cout << "SM2 [keyPair.pub()] = " << keyPair.pub() << endl;
        // SM3
        h256 hash(fromHex("44DB476208775A0E5DBD7C00D08833A7083E232DFA95788E2EC7CC231772C23A"));
        h256 r(fromHex("FA30BA6D44A9CA88FDBA5EF153C86605DAB9C24B44E1804FC802E73B81D04FE9"));
        h256 s(fromHex("B09D1335ED0CA9A3ECF20607789FC1DD9EBA5ECF5C65F7C916863629336794D4"));
        h512 v(keyPair.pub());
        SignatureStruct signature(r, s, v);
    
        // cout << "SM2 verify signature = " << toHex(dev::Signature(signature).r) << toHex(dev::Signature(signature).s) << endl;
        // cout << "SM2 signature = " << toHex(signature.r) << toHex(signature.s)   << endl;

        cout << "hash = " << hash << endl;
        cout << "secretKey = " << toHex(secret.ref()) << endl;
        cout << "SM2 [keyPair.pub()] = " << keyPair.pub() << endl;
        cout << "SM2 verify signature with pub = " << dev::Signature(signature) << endl;
        cout << "SM2 verfiy result = " << verify(v, signature, hash) << endl;
    }

    {
        auto plainText = fromHex("00"); 
        auto hash = dev::sha3(&plainText);
        cout << "sm3 data = " << toHex(plainText) << endl;
        cout << "sm3 digset = " << hash << endl;
    }
#else
for (int i = 0; i < 5; i++)
    {
        cout << endl;

        cout << "Testing AES PKCS#7 mode encrypt" << version << " ..." << endl;
        auto key = fromHex(toHex(dev::Secret::random().ref()));
        cout << "key = " << toHex(key) << endl;


        auto data = fromHex(toHex(dev::Secret::random().ref()));

        cout << "data = " << toHex(data) << endl;

        auto encryptedData = bytes();

        encryptedData = dev::aesCBCEncrypt(&data, &key);

        cout << " AES PKCS#7 encryptedData = " << toHex(encryptedData) << endl;

        auto decryptedData = bytes();

        decryptedData = dev::aesCBCDecrypt(&encryptedData, &key);
        cout << "AES PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    }

    for (int i = 0; i < 5; i++)
    {
        cout << endl;
        cout << "Testing ECDSA sign" << version << " ..." << endl;
        KeyPair keyPair = KeyPair::create();
        cout << "ECDSA [keyPair.pub()] = " << keyPair.pub() << endl;
        cout << "ECDSA [keyPair.secret()] = " << keyPair.secret() << endl;
        cout << "ECDSA [keyPair.secret().ref()] = " << toHex(keyPair.secret().ref()) << endl;
        // cout << "SM2 [keyPair.secret().ref() to pub] = " << toPublic(keyPair.secret().ref()) << endl;
        // SM3
        h256 hash(dev::Secret::random().ref());
        cout << "ECDSA messegae = " << hash << endl;

        Signature signature;
        signature = sign(keyPair.secret(), hash);
        h512 v(keyPair.pub());
        cout << "ECDSA verify signature with pub = " << dev::Signature(signature) << endl;
        cout << "ECDSA verfiy result = " << verify(v, signature, hash) << endl;
    }

    for (int i = 0; i < 5; i++)
    {
        // h256 hash(dev::Secret::random().ref());
        auto string = dev::Secret::random().ref();
        cout << "messgae = " << toHex(string) << endl;
        auto hash = dev::sha3(string);
        cout << "sha3 = " << hash << endl;
    }

    for (int i = 0; i < 5; i++)
    {
        // h256 hash(dev::Secret::random().ref());
        auto string = dev::Secret::random().ref();
        cout << "messgae = " << toHex(string) << endl;
        auto hash = dev::sha256(string);
        cout << "sha256 = " << hash << endl;
    }
    // {
    //     cout << endl;

    //     cout << "Testing AES-256 PKCS#7 mode encrypt" << version << " ..." << endl;
    //     auto key = fromHex("00000000000000000000000000000000");
    //     cout << "key = " << toHex(key) << endl;

    //     // auto iv = key;
    //     // cout << "iv = " << toHex(iv) << endl;

    //     // auto data = fromHex(
    //     //     "F00886825BD92FC8CC0C4149735FDB42F7B2D07A8699FD58E20EC55EE952DC2B516826A6857F53DB87ED72D25CC640661DE5F95C43FF648A0A075EF0D700B4F2");

    //     // cout << "data = " << toHex(data) << endl;
    //     // auto encryptedData = bytes();

    //     // encryptedData = dev::aesCBCEncrypt(&data, &key);

    //     auto encryptedData = fromHex("AB3D45F8FDF4A79234B8FB43E8A2B87309D6ABC7EA728FEE4E4557C984B11BA3B9E700DA322A82DD09C7F5E5B65D8A7A1353EEDB99629D9A7032397EF964CF8423FE9C18171A7A3C972E175E30CD7D04");



    //     cout << " AES-256 PKCS#7 encryptedData = " << toHex(encryptedData) << endl;

    //     auto decryptedData = bytes();

    //     decryptedData = dev::aesCBCDecrypt(&encryptedData, &key);
    //     cout << "AES-256 PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    // }

    // {
    //     cout << endl;

    //     cout << "Testing AES-256 PKCS#7 mode decrypt" << version << " ..." << endl;
    //     auto key = fromHex("6D01E156ADEFFD254FB469B7C167BA776558300D92AB42B0906A8FC97F06EE78");
    //     cout << "key = " << toHex(key) << endl;

    //     auto encryptedData = fromHex(
    //         "26C1842595EA4710E0F5FD4F83037F10");

    //     cout << "encryptedData = " << toHex(encryptedData) << endl;

    //     auto decryptedData = dev::aesCBCDecrypt(&encryptedData, &key);
    //     cout << "AES-256 PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    // }

    // {
    //     cout << endl;

    //     cout << "Testing AES-256 PKCS#7 mode decrypt" << version << " ..." << endl;
    //     auto key = fromHex("B462DDFADFB052FC44B12F997B97939CA0F11F48E96FE841012D7396970BD9E1");
    //     cout << "key = " << toHex(key) << endl;

    //     auto encryptedData = fromHex(
    //         "045413A7B0ED16C987A9F6EDEC61A84620AF91AAF05329C86EEC99C25DF2ED6F1B52BDCFE4A15212C3A8BC1696D98199102A7D98E8BA1086B394ED3A57A27A7A");

    //     cout << "encryptedData = " << toHex(encryptedData) << endl;

    //     auto decryptedData = dev::aesCBCDecrypt(&encryptedData, &key);
    //     cout << "AES-256 PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    // }

    // {
    //     cout << endl;
    //     cout << "Testing ECDSA key pair generate" << version << " ..." << endl;

    //     bytes bytesKey =
    //         fromHex("F433FA2F17DCE76233C6C22F5636DC65B59C55CF48FFF4ABA92CF3E1BB2942A9");
    //     Secret secret(bytesKey);
    //     cout << "secretKey = " << toHex(secret.ref()) << endl;
    //     KeyPair keyPair(secret);
    //     cout << "ECDSA secp256k1 [keyPair.pub()] = " << keyPair.pub() << endl;
    // }

    // {
    //     cout << endl;
    //     cout << "Testing ECDSA key pair generate" << version << " ..." << endl;

    //     bytes bytesKey =
    //         fromHex("EDF4B2432FD5F6FE4A3C3E7327C0942F8EEB71A19FC6A961E833686952EDA740");
    //     Secret secret(bytesKey);
    //     cout << "secretKey = " << toHex(secret.ref()) << endl;
    //     KeyPair keyPair(secret);
    //     cout << "ECDSA secp256k1 [keyPair.pub()] = " << keyPair.pub() << endl;
    // }

    // {
    //     cout << endl;
    //     cout << "Testing ECDSA key pair generate" << version << " ..." << endl;

    //     bytes bytesKey =
    //         fromHex("E5DEE91B97DBB13E652F1780D076E44C1AAA774883EAF1A4DFBD2FCE2C6175EF");
    //     Secret secret(bytesKey);
    //     cout << "secretKey = " << toHex(secret.ref()) << endl;
    //     KeyPair keyPair(secret);
    //     cout << "ECDSA secp256k1 [keyPair.pub()] = " << keyPair.pub() << endl;
    // }

    // {
    //     cout << endl;
    //     cout << "Testing ECDSA key pair generate" << version << " ..." << endl;

    //     bytes bytesKey =
    //         fromHex("C774CC891C0F019789A02C7C87F31E38445BAA01207092E2F5D49554B2C8D941");
    //     Secret secret(bytesKey);
    //     cout << "secretKey = " << toHex(secret.ref()) << endl;
    //     KeyPair keyPair(secret);
    //     cout << "ECDSA secp256k1 [keyPair.pub()] = " << keyPair.pub() << endl;
    // }

    // {
    //     cout << endl;
    //     cout << "Testing ECDSA key pair generate" << version << " ..." << endl;

    //     bytes bytesKey =
    //         fromHex("F433FA2F17DCE76233C6C22F5636DC65B59C55CF48FFF4ABA92CF3E1BB2942A9");
    //     Secret secret(bytesKey);
    //     cout << "secretKey = " << toHex(secret.ref()) << endl;
    //     KeyPair keyPair(secret);
    //     cout << "ECDSA secp256k1 [keyPair.pub()] = " << keyPair.pub() << endl;
    // }

    // {
    //     cout << endl;
    //     cout << "Testing ECDSA sign" << version << " ..." << endl;
    //     bytes bytesKey =
    //         fromHex("D69511773D09D9D56F6CFE0B628C152A9B1384930A1D317C77820880C8FC676B");
    //     Secret secret(bytesKey);
    //     cout << "secretKey = " << toHex(secret.ref()) << endl;
    //     KeyPair keyPair(secret);
    //     cout << "ECDSA [keyPair.pub()] = " << keyPair.pub() << endl;
    //     h256 hash(fromHex("0B96964C9A6C9118A4254343C77F8D98165A37EF9C65308BFBF1203548997C21"));
    //     cout << "ECDSA [Sign.message] = " << hash << endl;

    //     Signature signature;
    //     signature = sign(keyPair.secret(), hash);
    //     cout << "ECDSA signature with V = " << dev::Signature(signature) << endl;

    //     cout << "ECDSA verfiy result = " << verify(keyPair.pub(), signature, hash) << endl;
    // }

    // {
    //     cout << endl;
    //     cout << "Testing ECDSA sign" << version << " ..." << endl;
    //     bytes bytesKey =
    //         fromHex("B75EFF3026D77DF3813F7F06DECC2B9E9323EB8113609AE8C7BB129B799E3659");
    //     Secret secret(bytesKey);
    //     cout << "secretKey = " << toHex(secret.ref()) << endl;
    //     KeyPair keyPair(secret);
    //     cout << "ECDSA [keyPair.pub()] = " << keyPair.pub() << endl;
    //     h256 hash(fromHex("BFC03D74F872BA2B4BEBAF5846DE89AE1096D0C71D4C002B2380466A6ADACFF3"));
    //     cout << "ECDSA [Sign.message] = " << hash << endl;

    //     Signature signature;
    //     signature = sign(keyPair.secret(), hash);
    //     cout << "ECDSA signature with V = " << dev::Signature(signature) << endl;

    //     cout << "ECDSA verfiy result = " << verify(keyPair.pub(), signature, hash) << endl;
    // }

    // {
    //     cout << endl;
    //     cout << "Testing ECDSA sign" << version << " ..." << endl;
    //     bytes bytesKey =
    //         fromHex("82E80B9811F416AA8732990CE1F6544E94565B791ED7C1C54E33C0860913ECB3");
    //     Secret secret(bytesKey);
    //     cout << "secretKey = " << toHex(secret.ref()) << endl;
    //     KeyPair keyPair(secret);
    //     cout << "ECDSA [keyPair.pub()] = " << keyPair.pub() << endl;
    //     h256 hash(fromHex("7EBB6A9335DFFA86F17D922423B56C48AB0EB794F640248D318B971F04517571"));
    //     cout << "ECDSA [Sign.message] = " << hash << endl;

    //     Signature signature;
    //     signature = sign(keyPair.secret(), hash);
    //     cout << "ECDSA signature with V = " << dev::Signature(signature) << endl;

    //     cout << "ECDSA verfiy result = " << verify(keyPair.pub(), signature, hash) << endl;
    // }



    // {
    //     cout << endl;
    //     cout << "Testing ECDSA verify" << version << " ..." << endl;
    //     bytes bytesKey =
    //         fromHex("E5DEE91B97DBB13E652F1780D076E44C1AAA774883EAF1A4DFBD2FCE2C6175EF");
    //     Secret secret(bytesKey);
    //     cout << "secretKey = " << toHex(secret.ref()) << endl;
    //     KeyPair keyPair(secret);
    //     cout << "ECDSA [keyPair.pub()] = " << keyPair.pub() << endl;
    //     h256 hash(fromHex("5D53469F20FEF4F8EAB52B88044EDE69C77A6A68A60728609FC4A65FF531E7D0"));
    //     cout << "ECDSA [Sign.message] = " << hash << endl;

    //     // h256 r(fromHex("e8644980bfb2e5aa0b4c84e1d5fe67c7af93147416477eaf8c188325bff42285"));
    //     // h256 s(fromHex("62aeb6aeb44913a0150591ec65ef83c454da75338c6252053e28dd8c691b886b"));
    //     // uint8_t v(0);
        
    //     h256 r(fromHex("41042d69ec6ce4acddcc704ad26ea651361d5f59a001f9e5b4a33b5c58196e7b"));
    //     h256 s(fromHex("6f84f812d2beda059fe0bef3ace87adbd49ac020103177ed9e1b0c7a006f3459"));
    //     uint8_t v(1);
    //     cout << "ECDSA [r] = " << r << endl;
    //     cout << "ECDSA [s] = " << s << endl;
    //     cout << "ECDSA [v] = " << v << endl;

    //     SignatureStruct signature(r, s, v);
    //     cout << "ECDSA verify signature with pub = " << dev::Signature(signature) << endl;

    //     cout << "ECDSA verfiy result = " << verify(keyPair.pub(), signature, hash) << endl;
    // }

    // {
    // const std::string plainText = "00";
    // cout << "message = " << plainText << endl;
    // bytes bs;
    // for (size_t i = 0; i < plainText.length(); i++)
    // {
    //     bs.push_back((byte)plainText[i]);
    // }
    // bytesConstRef bsConst(&bs);

    //     auto hash = dev::sha256(bsConst);
    //     cout << "sha256 = " << hash << endl;
    // }

    // {
    // const std::string plainText = "0000000000000000";
    // cout << "message = " << plainText << endl;
    // bytes bs;
    // for (size_t i = 0; i < plainText.length(); i++)
    // {
    //     bs.push_back((byte)plainText[i]);
    // }
    // bytesConstRef bsConst(&bs);

    //     auto hash = dev::sha256(bsConst);
    //     cout << "sha256 = " << hash << endl;
    // }

    // {
    // const std::string plainText = "11C0F655A99AC78E91921B2CDDCB4BCEAED871ECE266FDFD0F7D4F51A5E3ED28";
    // cout << "message = " << plainText << endl;
    // bytes bs;
    // for (size_t i = 0; i < plainText.length(); i++)
    // {
    //     bs.push_back((byte)plainText[i]);
    // }
    // bytesConstRef bsConst(&bs);

    //     auto hash = dev::sha256(bsConst);
    //     cout << "sha256 = " << hash << endl;
    // }

    // {
    // const std::string plainText = "D321F67C4B9C35E837FFCD7529B00E582AB6D7B1E7988992602632B799525BD55D7BBF";
    // cout << "message = " << plainText << endl;
    // bytes bs;
    // for (size_t i = 0; i < plainText.length(); i++)
    // {
    //     bs.push_back((byte)plainText[i]);
    // }
    // bytesConstRef bsConst(&bs);

    //     auto hash = dev::sha256(bsConst);
    //     cout << "sha256 = " << hash << endl;
    // }


    // {
    // const std::string plainText = "599EFEBB8E1BCE7F7B9F8C5AE045A050302106DE65A3569EFB6ECCD3BB07DC9FE24BAF3B337AAEA52A603F66F339762488395983C1AA103DF625DE6486318FDE0BD25796F7254A02007E1CA72F14F7331F889F4D37012E294D641C52F80B6C3D87C5270E";
    // cout << "message = " << plainText << endl;
    // bytes bs;
    // for (size_t i = 0; i < plainText.length(); i++)
    // {
    //     bs.push_back((byte)plainText[i]);
    // }
    // bytesConstRef bsConst(&bs);

    //     auto hash = dev::sha256(bsConst);
    //     cout << "sha256 = " << hash << endl;
    // }


// {
//     const std::string plainText = "00";
//     cout << "message = " << plainText << endl;
//     bytes bs;
//     for (size_t i = 0; i < plainText.length(); i++)
//     {
//         bs.push_back((byte)plainText[i]);
//     }
//     bytesConstRef bsConst(&bs);

//     auto hash = dev::sha3(bsConst);
//     cout << "sha3 = " << hash << endl;

// }

// {
//     const std::string plainText = "00000000";
//     cout << "message = " << plainText << endl;
//     bytes bs;
//     for (size_t i = 0; i < plainText.length(); i++)
//     {
//         bs.push_back((byte)plainText[i]);
//     }
//     bytesConstRef bsConst(&bs);

//     auto hash = dev::sha3(bsConst);
//     cout << "sha3 = " << hash << endl;

// }

// {
//     const std::string plainText = "BC5B1B0551812856EDD0C98D874E2D2DB5396E13E71D0AF42F9FC7269021C732";
//     cout << "message = " << plainText << endl;
//     bytes bs;
//     for (size_t i = 0; i < plainText.length(); i++)
//     {
//         bs.push_back((byte)plainText[i]);
//     }
//     bytesConstRef bsConst(&bs);

//     auto hash = dev::sha3(bsConst);
//     cout << "sha3 = " << hash << endl;

// }

// {
//     const std::string plainText = "36ECC790727B244298E5E68DA313C60FA2EB776F21E27C5CBEE894CB7AD1C50BB6A195";
//     cout << "message = " << plainText << endl;
//     bytes bs;
//     for (size_t i = 0; i < plainText.length(); i++)
//     {
//         bs.push_back((byte)plainText[i]);
//     }
//     bytesConstRef bsConst(&bs);

//     auto hash = dev::sha3(bsConst);
//     cout << "sha3 = " << hash << endl;

// }

    {
        auto plainText = fromHex("00"); 
        auto hash = dev::sha3(&plainText);
        cout << "keccak data = " << toHex(plainText) << endl;
        cout << "keccak digset = " << hash << endl;

        auto hash = dev::sha256(&plainText);
        cout << "sha256 data = " << toHex(plainText) << endl;
        cout << "sha256 digset = " << hash << endl;
    }

#endif
    return 0;
}
