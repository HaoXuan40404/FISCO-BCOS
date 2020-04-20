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

        {
        cout << endl;

        cout << "Testing SM4 PKCS#7 mode encrypt" << version << " ..." << endl;
        auto key = fromHex("69C6A82B230934545747DAF2D84C9939");  // GM
        auto iv = fromHex("00000000000000000000000000000000");  // GM
        auto data = fromHex(
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");  // GM
        auto encryptedData = dev::aesCBCEncrypt(&data, &key, &iv);
        auto decryptedData = bytes();

        decryptedData = dev::aesCBCDecrypt(&encryptedData, &key, &iv);
        cout << "data = " << toHex(data) << endl;
        cout << "key = " << toHex(key) << endl;
        cout << "iv = " << toHex(iv) << endl;
        cout << " SM4 PKCS#7 encryptedData = " << toHex(encryptedData) << endl;
        cout << "SM4 PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    }

    {
        cout << endl;

        cout << "Testing SM4 PKCS#7 mode decrypt" << version << " ..." << endl;
        auto key = fromHex("00000000000000000000000000000000");  // GM
        auto iv = fromHex("97268147F9ECFEFD9584840E475F06B9");  // GM
        auto encryptedData = fromHex("28BF66C46A7A876DB516396A403F90789D2CA4CCE5D59D352F176EF2C40CC387C81B187D374FFE53BE12720D395CB58E7CA8D69E2A0D5EFE687F3B3821C84584"); 
        auto decryptedData = bytes();
        decryptedData = dev::aesCBCDecrypt(&encryptedData, &key, &iv);
        cout << " SM4 PKCS#7 encryptedData = " << toHex(encryptedData) << endl;
        cout << "key = " << toHex(key) << endl;
        cout << "iv = " << toHex(iv) << endl;
        cout << "SM4 PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    }

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
            fromHex("4B522E7E65EEA7CC2427239AD403E5FAE654810A685173A91334A33E6E7DCFA8");
        Secret secret(bytesKey);
        KeyPair keyPair(secret);
        // SM3
        h256 hash(fromHex("2DAEF60E7A0B8F5E024C81CD2AB3109F2B4F155CF83ADEB2AE5532F74A157FDF"));


        Signature signature;
        signature = sign(keyPair.secret(), hash);
        h512 v(keyPair.pub());
        cout << "SM2 [hash ] = " << toHex(hash) << endl;
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
    {
        cout << endl;

        cout << "Testing AES PKCS#7 mode encrypt" << version << " ..." << endl;
        auto key = fromHex("69C6A82B230934545747DAF2D84C9939");  // GM
        auto iv = fromHex("00000000000000000000000000000000");  // GM
        auto data = fromHex(
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");  // GM
        auto encryptedData = dev::aesCBCEncrypt(&data, &key, &iv);
        auto decryptedData = bytes();

        decryptedData = dev::aesCBCDecrypt(&encryptedData, &key, &iv);
        cout << "data = " << toHex(data) << endl;
        cout << "key = " << toHex(key) << endl;
        cout << "iv = " << toHex(iv) << endl;
        cout << " AES PKCS#7 encryptedData = " << toHex(encryptedData) << endl;
        cout << "AES PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    }

    // {
    //     cout << endl;

    //     cout << "Testing AES PKCS#7 mode decrypt" << version << " ..." << endl;
    //     auto key = fromHex("00000000000000000000000000000000");  // GM
    //     auto iv = fromHex("97268147F9ECFEFD9584840E475F06B9");  // GM
    //     auto encryptedData = fromHex("28BF66C46A7A876DB516396A403F90789D2CA4CCE5D59D352F176EF2C40CC387C81B187D374FFE53BE12720D395CB58E7CA8D69E2A0D5EFE687F3B3821C84584"); 
    //     auto decryptedData = bytes();
    //     decryptedData = dev::aesCBCDecrypt(&encryptedData, &key, &iv);
    //     cout << " AES PKCS#7 encryptedData = " << toHex(encryptedData) << endl;
    //     cout << "key = " << toHex(key) << endl;
    //     cout << "iv = " << toHex(iv) << endl;
    //     cout << "AES PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    // }

        {
        cout << endl;
        cout << "Testing ECDSA-secp256k1 key pair generate" << version << " ..." << endl;
        bytes bytesKey =
            fromHex("4B522E7E65EEA7CC2427239AD403E5FAE654810A685173A91334A33E6E7DCFA8");  // GM

        Secret secret(bytesKey);
        cout << "secretKey = " << toHex(secret.ref()) << endl;
        KeyPair keyPair(secret);
        cout << "ECDSA-secp256k1 [keyPair.pub()] = " << keyPair.pub() << endl;
    }
    

    {
        cout << endl;
        cout << "Testing ECDSA-secp256k1 sign" << version << " ..." << endl;
        bytes bytesKey =
            fromHex("4B522E7E65EEA7CC2427239AD403E5FAE654810A685173A91334A33E6E7DCFA8");
        Secret secret(bytesKey);
        KeyPair keyPair(secret);
        // SM3
        h256 hash(fromHex("2DAEF60E7A0B8F5E024C81CD2AB3109F2B4F155CF83ADEB2AE5532F74A157FDF"));


        Signature signature;
        signature = sign(keyPair.secret(), hash);
        h512 v(keyPair.pub());
        cout << "ECDSA-secp256k1 [hash ] = " << toHex(hash) << endl;
        cout << "secretKey = " << toHex(secret.ref()) << endl;
        cout << "ECDSA-secp256k1 [keyPair.pub()] = " << keyPair.pub() << endl;
        cout << "ECDSA-secp256k1 verify signature with V = " << dev::Signature(signature) << endl;
        cout << "ECDSA-secp256k1 verfiy result = " << verify(v, signature, hash) << endl;
    }
    

    // {
    //     cout << endl;
    //     cout << "Testing ECDSA-secp256k1 verify" << version << " ..." << endl;
    //     bytes bytesKey =
    //         fromHex("D96C222D8602B287973E2ACA7E3FEDADFD0BD67F2914D3E16F46FAB8A8506F2B");
    //     Secret secret(bytesKey);
    //     cout << "secretKey = " << toHex(secret.ref()) << endl;
    //     KeyPair keyPair(secret);
    //     cout << "ECDSA-secp256k1 [keyPair.pub()] = " << keyPair.pub() << endl;
    //     // SM3
    //     h256 hash(fromHex("44DB476208775A0E5DBD7C00D08833A7083E232DFA95788E2EC7CC231772C23A"));
    //     h256 r(fromHex("FA30BA6D44A9CA88FDBA5EF153C86605DAB9C24B44E1804FC802E73B81D04FE9"));
    //     h256 s(fromHex("B09D1335ED0CA9A3ECF20607789FC1DD9EBA5ECF5C65F7C916863629336794D4"));
    //     h512 v(keyPair.pub());
    //     SignatureStruct signature(r, s, v);
    

    //     cout << "hash = " << hash << endl;
    //     cout << "secretKey = " << toHex(secret.ref()) << endl;
    //     cout << "ECDSA-secp256k1 [keyPair.pub()] = " << keyPair.pub() << endl;
    //     cout << "ECDSA-secp256k1 verify signature with V = " << dev::Signature(signature) << endl;
    //     cout << "ECDSA-secp256k1 verfiy result = " << verify(v, signature, hash) << endl;
    // }

    {
        auto plainText = fromHex("00"); 
        auto hash = dev::sha3(&plainText);
        cout << "keccak data = " << toHex(plainText) << endl;
        cout << "keccak digset = " << hash << endl;
    }
    {
        auto plainText = fromHex("00"); 
        auto hash = dev::sha256(&plainText);
        cout << "sha256 data = " << toHex(plainText) << endl;
        cout << "sha256 digset = " << hash << endl;
    }

#endif
    return 0;
}
