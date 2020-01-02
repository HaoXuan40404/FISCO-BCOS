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
        auto key = fromHex("00000000000000000000000000000000");  // GM
        cout << "key = " << toHex(key) << endl;

        auto iv = key;
        cout << "iv = " << toHex(iv) << endl;

        auto data = fromHex(
            "5942D6DA31CD0A93E46CF382468710888F4393C6D734B3C6C6C44B1F6F34B08AEE0386B91831A268C4E981"
            "5BB61375F4CDA913BA80C37CE6F4971977319CCD7D23502328A45130D0FDF5B63A77EA601F806733FBCADF"
            "969B08AA9AA56A8B509FAA7E95FC3706E3482EF1532A91DB2EB3EDF234D1E2E57F75B5EACC81A391b17a");
        // GM

        cout << "data = " << toHex(data) << endl;

        auto encryptedData = bytes();

        encryptedData = dev::aesCBCEncrypt(&data, &key);

        cout << " SM4 PKCS#7 encryptedData = " << toHex(encryptedData) << endl;

        auto decryptedData = bytes();

        decryptedData = dev::aesCBCDecrypt(&encryptedData, &key);
        cout << "SM4 PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    }

    {
        cout << endl;

        cout << "Testing SM4 PKCS#7 mode decrypt" << version << " ..." << endl;
        auto key = fromHex("00000000000000000000000000000000");  // GM

        cout << "key = " << toHex(key) << endl;

        auto iv = key;
        cout << "iv = " << toHex(iv) << endl;

        auto encryptedData = fromHex(
            "96E0C7C8BAB556323C329517CFA22726FCA8CE6137EBB87E0C85BB64DBEDE9EA57D5F9800D66D2D3496DF8"
            "5C9B605EAFC95859CABF833B5A888A0B9840F5CA1E");  // GM

        cout << "encryptedData = " << toHex(encryptedData) << endl;

        auto decryptedData = dev::aesCBCDecrypt(&encryptedData, &key);
        cout << "SM4 PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    }

    {
        cout << endl;
        cout << "Testing SM2 key pair generate" << version << " ..." << endl;
        bytes bytesKey =
            fromHex("D112A30BD76974B24C49ED1B3A3C21B0B2870D334B256E26290DB04549CD7CD1");  // GM

        Secret secret(bytesKey);
        cout << "secretKey = " << toHex(secret.ref()) << endl;
        KeyPair keyPair(secret);
        cout << "ECDSA/SM2 [keyPair.pub()] = " << keyPair.pub() << endl;
    }

    {
        cout << endl;
        cout << "Testing SM2 sign" << version << " ..." << endl;
        bytes bytesKey =
            fromHex("4B522E7E65EEA7CC2427239AD403E5FAE654810A685173A91334A33E6E7DCFA8");
        Secret secret(bytesKey);
        cout << "secretKey = " << toHex(secret.ref()) << endl;
        KeyPair keyPair(secret);
        cout << "ECDSA/SM2 [keyPair.pub()] = " << keyPair.pub() << endl;
        // SM3
        h256 hash(fromHex("2DAEF60E7A0B8F5E024C81CD2AB3109F2B4F155CF83ADEB2AE5532F74A157FDF"));

        Signature signature;
        signature = sign(keyPair.secret(), hash);
        cout << "SM2 signature with pub = " << dev::Signature(signature) << endl;
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

        cout << "hash = " << hash << endl;


        h256 r(fromHex("CDCE0FA4D91ACF9147FBC9A0BDD3F9B6A3CFF4E7909A2D638AE58CE60578A2DC"));
        h256 s(fromHex("1EAAE69D26B275FA6B65E89C7DCE1CAE59BEA7F0C6E12E89084F08FB662B872F"));
        h512 v(keyPair.pub());
        SignatureStruct signature(r, s, v);
        cout << "SM2 verify signature with pub = " << dev::Signature(signature) << endl;

        cout << "SM2 verfiy result = " << verify(v, signature, hash) << endl;
    }
#else
    {
        cout << endl;

        cout << "Testing AES-256 PKCS#7 mode encrypt" << version << " ..." << endl;
        auto key = fromHex("0000000000000000000000000000000000000000000000000000000000000000");
        cout << "key = " << toHex(key) << endl;

        auto iv = key;
        cout << "iv = " << toHex(iv) << endl;

        auto data = fromHex(
            "2B731E559C35EB31AD86EA0EAA441F198B8F0291C3F091F535F5B6DF65498D11EA3028B97E1642D69F9B73"
            "44A257EA5EEEB256A2AA865DE86E81A9846BB4E625");

        cout << "data = " << toHex(data) << endl;

        auto encryptedData = bytes();

        encryptedData = dev::aesCBCEncrypt(&data, &key);

        cout << " AES-256 PKCS#7 encryptedData = " << toHex(encryptedData) << endl;

        auto decryptedData = bytes();

        decryptedData = dev::aesCBCDecrypt(&encryptedData, &key);
        cout << "AES-256 PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    }

    {
        cout << endl;

        cout << "Testing AES-256 PKCS#7 mode decrypt" << version << " ..." << endl;
        auto key = fromHex("0000000000000000000000000000000000000000000000000000000000000000");
        cout << "key = " << toHex(key) << endl;

        auto iv = key;
        cout << "iv = " << toHex(iv) << endl;

        auto encryptedData = fromHex(
            "AB3D45F8FDF4A79234B8FB43E8A2B87309D6ABC7EA728FEE4E4557C984B11BA3B9E700DA322A82DD09C7F5"
            "E5B65D8A7A1353EEDB99629D9A7032397EF964CF8423FE9C18171A7A3C972E175E30CD7D04");

        cout << "encryptedData = " << toHex(encryptedData) << endl;

        auto decryptedData = dev::aesCBCDecrypt(&encryptedData, &key);
        cout << "AES-256 PKCS#7 decryptedData = " << toHex(decryptedData) << endl;
    }

    {
        cout << endl;
        cout << "Testing ECDSA/SM2 key pair generate" << version << " ..." << endl;

        bytes bytesKey =
            fromHex("F433FA2F17DCE76233C6C22F5636DC65B59C55CF48FFF4ABA92CF3E1BB2942A9");
        Secret secret(bytesKey);
        cout << "secretKey = " << toHex(secret.ref()) << endl;
        KeyPair keyPair(secret);
        cout << "ECDSA secp256k1 [keyPair.pub()] = " << keyPair.pub() << endl;
    }

    {
        cout << endl;
        cout << "Testing ECDSA sign" << version << " ..." << endl;
        bytes bytesKey =
            fromHex("88AF94B9E261CAEAAF7973F60B65465B410CAB4D783ACCDB1DEA5D0153FFECA5");
        Secret secret(bytesKey);
        cout << "secretKey = " << toHex(secret.ref()) << endl;
        KeyPair keyPair(secret);
        cout << "ECDSA [keyPair.pub()] = " << keyPair.pub() << endl;
        h256 hash(fromHex("5D53469F20FEF4F8EAB52B88044EDE69C77A6A68A60728609FC4A65FF531E7D0"));

        Signature signature;
        signature = sign(keyPair.secret(), hash);
        cout << "ECDSA/SM2 signature with pub = " << dev::Signature(signature) << endl;
    }

    // {
    //     cout << endl;
    //     cout << "Testing ECDSA verify" << version << " ..." << endl;
    //     bytes bytesKey =
    //         fromHex("D96C222D8602B287973E2ACA7E3FEDADFD0BD67F2914D3E16F46FAB8A8506F2B");
    //     Secret secret(bytesKey);
    //     cout << "secretKey = " << toHex(secret.ref()) << endl;
    //     KeyPair keyPair(secret);
    //     cout << "ECDSA [keyPair.pub()] = " << keyPair.pub() << endl;
    //     h256 hash(fromHex("2DAEF60E7A0B8F5E024C81CD2AB3109F2B4F155CF83ADEB2AE5532F74A157FDF"));

    //     cout << "hash = " << hash << endl;


    //     h256 r(fromHex("5356F5381FD5A35A75948E7D655CD153BE56E7D0008FDB0C54C0F60D4E53899C"));
    //     h256 s(fromHex("90BC7949B959A49603B61F27E5F0B2B15402318D9E17BB08566DDBCD30A16354"));
    //     h512 pub(keyPair.pub());
        
    //     byte b = 27;

    //     SignatureStruct signature(r, s, b);
    //     cout << "ECDSA verify signature with pub = " << dev::Signature(signature) << endl;

    //     cout << "ECDSA verfiy result = " << verify(pub, signature, hash) << endl;
    // }
#endif
    return 0;
}
