#include "SignUtils.h"

void handleError(const char* err)
{
    DWORD lastError = GetLastError();
    printf("%s: %04x\n\thttps://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-", err, lastError);
    ExitProcess(lastError);
}

void handleNtError(const char* err, NTSTATUS val)
{
    const char* ntStatusSignification = NULL;
    switch (val)
    {
    case STATUS_INVALID_HANDLE:
        ntStatusSignification = "The algorithm handle in the hAlgorithm parameter is not valid.";
        break;
    case STATUS_INVALID_PARAMETER:
        ntStatusSignification = "One or more parameters are not valid.";
        break;
    case 0xC00000BBL: //STATUS_NOT_SUPPORTED
        ntStatusSignification = "The specified provider does not support asymmetric key encryption.";
        break;
    case 0xC0000225L: //STATUS_NOT_FOUND
        ntStatusSignification = "No provider was found for the specified algorithm ID...";
        break;
    case 0x80090005L: //STATUS_BAD_DATA
        ntStatusSignification = "Bad data!";
        break;
    default:
        ntStatusSignification = "Unknown error";
    }
    printf("%s: %08x\n\t%s\n\thttps://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-", err, val, ntStatusSignification);
    ExitProcess(val);
}

void hexdump(void* ptr, int buflen)
{
    unsigned char* buf = (unsigned char*)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16) {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        printf(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        printf("\n");
    }
}

BCRYPT_ALG_HANDLE getCryptoProvider()
{
    NTSTATUS ret;
    BCRYPT_ALG_HANDLE tmpProvider;
    if (ret = BCryptOpenAlgorithmProvider(&tmpProvider, BCRYPT_RSA_ALGORITHM, NULL, 0))
    {
        handleNtError("Couldn't get the BCRYPT_RSA_ALGORITHM provider", ret);
    }
    return tmpProvider;
}

BCRYPT_KEY_HANDLE generateKeys(BCRYPT_ALG_HANDLE cryptoProvider)
{
    NTSTATUS ret;
    BCRYPT_KEY_HANDLE tmpKey = NULL;
    if (ret = BCryptGenerateKeyPair(cryptoProvider, &tmpKey, 2048, 0))
    {
        handleNtError("Couldn't create the RSA 2048 bits keypair", ret);
    }
    if (ret = BCryptFinalizeKeyPair(tmpKey, 0))
    {
        handleNtError("Couldn't finalise the RSA 2048 bits keypair", ret);
    }
    return tmpKey;
}

BCRYPT_KEY_HANDLE getPrivkeyBlobFromB64(BCRYPT_ALG_HANDLE cryptoProvider, std::string b64data)
{
    NTSTATUS ret;
    BCRYPT_KEY_HANDLE tmpKey = NULL;
    BYTE* tmpBuffer = (BYTE*)malloc(4096);
    size_t writtenBytes = 0;
    std::pair<std::size_t, std::size_t> res = boost::beast::detail::base64::decode(tmpBuffer, b64data.c_str(), 4096, &writtenBytes);
    if (ret = BCryptImportKeyPair(cryptoProvider, NULL, BCRYPT_RSAPRIVATE_BLOB, &tmpKey, tmpBuffer, res.first, 0))
    {
        handleNtError("Couldn't get the length of the private key", ret);
    }
    free(tmpBuffer);
    return tmpKey;
}

BCRYPT_KEY_HANDLE getPubkeyBlobFromB64(BCRYPT_ALG_HANDLE cryptoProvider, std::string b64data)
{
    NTSTATUS ret;
    BCRYPT_KEY_HANDLE tmpKey = NULL;
    BYTE* tmpBuffer = (BYTE*)malloc(4096);
    size_t writtenBytes = 0;
    std::pair<std::size_t, std::size_t> res = boost::beast::detail::base64::decode(tmpBuffer, b64data.c_str(), 4096, &writtenBytes);
    if (ret = BCryptImportKeyPair(cryptoProvider, NULL, BCRYPT_RSAPUBLIC_BLOB, &tmpKey, tmpBuffer, res.first, 0))
    {
        handleNtError("Couldn't get the length of the public key", ret);
    }
    free(tmpBuffer);
    return tmpKey;
}

std::string hashToB64(BYTE* data, ULONG dataLength)
{
    //Create hash provider
    NTSTATUS ret = NULL;
    BCRYPT_ALG_HANDLE hashProvider = NULL;
    DWORD hashObjectSize = 0;
    BYTE* hashObject = NULL;
    BCRYPT_HASH_HANDLE hashHandle = NULL;
    BYTE* hashedData = NULL;
    DWORD hashedDataSize = 0;
    DWORD uselessVariable = 0;
    if (ret = BCryptOpenAlgorithmProvider(&hashProvider, BCRYPT_SHA256_ALGORITHM, NULL, 0))
    {
        handleNtError("Couldn't get the BCRYPT_SHA256_ALGORITHM provider", ret);
    }
    //Create hash object
    if (ret = BCryptGetProperty(hashProvider, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjectSize, sizeof(DWORD), &uselessVariable, 0))
    {
        handleNtError("Couldn't get the length of a hashing object", ret);
    }
    hashObject = (BYTE*)malloc(hashObjectSize);

    if (ret = BCryptGetProperty(hashProvider, BCRYPT_HASH_LENGTH, (PBYTE)&hashedDataSize, sizeof(DWORD), &uselessVariable, 0))
    {
        handleNtError("Couldn't get the length of a hash", ret);
    }
    hashedData = (BYTE*)malloc(hashedDataSize);
    if (hashedData == 0)
    {
        printf("Couldn't allocate memory for the result hash\n");
        ExitProcess(1);
    }

    if (ret = BCryptCreateHash(hashProvider, &hashHandle, hashObject, hashObjectSize, NULL, 0, 0))
    {
        handleNtError("Couldn't create the hash object and get a hash handle", ret);
    }
    //Hash data
    if (ret = BCryptHashData(hashHandle, (BYTE*)data, dataLength, 0))
    {
        handleNtError("Couldn't hash the data", ret);
    }
    if (ret = BCryptFinishHash(hashHandle, hashedData, hashedDataSize, 0))
    {
        handleNtError("Couldn't store the hash", ret);
    }

    std::string b64Hash = boost::beast::detail::base64_encode(hashedData, hashedDataSize);
    //Display it (we'll return it in the function)

    //Destroy hashed data
    free(hashedData);
    //Destroy hash object
    BCryptDestroyHash(hashHandle);
    free(hashObject);
    //Destroy hash provider
    BCryptCloseAlgorithmProvider(hashProvider, 0);
    return b64Hash;
}

std::string signData(BYTE* data, ULONG dataLength, BCRYPT_KEY_HANDLE privKey, BCRYPT_ALG_HANDLE cryptoProvider)
{
    //Create hash provider
    NTSTATUS ret = NULL;
    BCRYPT_ALG_HANDLE hashProvider = NULL;
    DWORD hashObjectSize = 0;
    BYTE* hashObject = NULL;
    BCRYPT_HASH_HANDLE hashHandle = NULL;
    BYTE* hashedData = NULL;
    DWORD hashedDataSize = 0;
    DWORD uselessVariable = 0;
    if (ret = BCryptOpenAlgorithmProvider(&hashProvider, BCRYPT_SHA256_ALGORITHM, NULL, 0))
    {
        handleNtError("Couldn't get the BCRYPT_SHA256_ALGORITHM provider", ret);
    }
    //Create hash object
    if (ret = BCryptGetProperty(hashProvider, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjectSize, sizeof(DWORD), &uselessVariable, 0))
    {
        handleNtError("Couldn't get the length of a hashing object", ret);
    }
    hashObject = (BYTE*)malloc(hashObjectSize);

    if (ret = BCryptGetProperty(hashProvider, BCRYPT_HASH_LENGTH, (PBYTE)&hashedDataSize, sizeof(DWORD), &uselessVariable, 0))
    {
        handleNtError("Couldn't get the length of a hash", ret);
    }
    hashedData = (BYTE*)malloc(hashedDataSize);
    if (hashedData == 0)
    {
        printf("Couldn't allocate memory for the result hash\n");
        ExitProcess(1);
    }

    if (ret = BCryptCreateHash(hashProvider, &hashHandle, hashObject, hashObjectSize, NULL, 0, 0))
    {
        handleNtError("Couldn't create the hash object and get a hash handle", ret);
    }
    //Hash data
    if (ret = BCryptHashData(hashHandle, (BYTE*)data, dataLength, 0))
    {
        handleNtError("Couldn't hash the data", ret);
    }
    if (ret = BCryptFinishHash(hashHandle, hashedData, hashedDataSize, 0))
    {
        handleNtError("Couldn't store the hash", ret);
    }
    //Encrypt/sign the hash (BCryptSignHash)
    DWORD signedHashSize = 0;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    if (ret = BCryptSignHash(privKey, NULL, hashedData, hashedDataSize, NULL, 0, &signedHashSize, 0)) //Get the length of a signed hash
    {
        handleNtError("Couldn't get the size of a signed hash", ret);
    }
    BYTE* signedHashedData = (BYTE*)malloc(signedHashSize);
    if (signedHashedData == 0)
    {
        printf("Couldn't allocate memory for the result signed hash\n");
        ExitProcess(1);
    }

    DWORD tmp;

    if (ret = BCryptSignHash(privKey, &paddingInfo, hashedData, hashedDataSize, signedHashedData, signedHashSize, &tmp, BCRYPT_PAD_PKCS1)) //Sign the hash
    {
        handleNtError("Couldn't sign the hash data", ret);
    }
    //hexdump(signedHashedData, signedHashSize);
    //Export the signed hash (b64 or hex, whichever is easiest)
    std::string b64signedHash = boost::beast::detail::base64_encode(signedHashedData, signedHashSize);
    //Display it (we'll return it in the function)

    //Destroy hashed data
    free(hashedData);
    //Destroy hash object
    BCryptDestroyHash(hashHandle);
    free(hashObject);
    //Destroy hash provider
    BCryptCloseAlgorithmProvider(hashProvider, 0);
    return b64signedHash;
}

bool checkSignature(BYTE* data, ULONG dataLength, std::string dataSignature, BCRYPT_KEY_HANDLE pubKey, BCRYPT_ALG_HANDLE cryptoProvider)
{
    //Optional: Verify we can check if the sig is correct
    BCRYPT_KEY_HANDLE pubKeyHandle = getPubkeyBlobFromB64(cryptoProvider, getB64Pubkey(pubKey));
    std::string dataHash = hashToB64(data, dataLength);

    BYTE* hashedDataBuffer = (BYTE*)malloc(4096);
    std::pair<std::size_t, std::size_t> res = boost::beast::detail::base64::decode(hashedDataBuffer, dataHash.c_str(), 4096, NULL);

    BYTE* signedHashBuffer = (BYTE*)malloc(4096);
    std::pair<std::size_t, std::size_t> res2 = boost::beast::detail::base64::decode(signedHashBuffer, dataSignature.c_str(), 4096, NULL);

    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    NTSTATUS isValidSig = BCryptVerifySignature(pubKeyHandle, &paddingInfo, hashedDataBuffer, res.first, signedHashBuffer, res2.first, BCRYPT_PAD_PKCS1) == 0;
    free(hashedDataBuffer);
    return isValidSig;
}

std::string getB64Privkey(BCRYPT_KEY_HANDLE privKey)
{
    NTSTATUS ret;
    ULONG expPrivKeySize = 0;
    if (ret = BCryptExportKey(privKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &expPrivKeySize, 0))
    {
        handleNtError("Couldn't get the length of the private key", ret);
    }
    BYTE* expPrivKey = (BYTE*)malloc(expPrivKeySize);
    if (ret = BCryptExportKey(privKey, NULL, BCRYPT_RSAPRIVATE_BLOB, expPrivKey, expPrivKeySize, &expPrivKeySize, 0))
    {
        handleNtError("Couldn't export the private key", ret);
    }
    //hexdump(expPrivKey, expPrivKeySize);
    return boost::beast::detail::base64_encode(expPrivKey, expPrivKeySize);
}

std::string getB64Pubkey(BCRYPT_KEY_HANDLE pubKey)
{
    NTSTATUS ret;
    ULONG expPubKeySize = 0;
    if (ret = BCryptExportKey(pubKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &expPubKeySize, 0))
    {
        handleNtError("Couldn't get the length of the public key", ret);
    }
    BYTE* expPubKey = (BYTE*)malloc(expPubKeySize);
    if (ret = BCryptExportKey(pubKey, NULL, BCRYPT_RSAPUBLIC_BLOB, expPubKey, expPubKeySize, &expPubKeySize, 0))
    {
        handleNtError("Couldn't export the public key", ret);
    }
    //hexdump(expPubKey, expPubKeySize);
    return boost::beast::detail::base64_encode(expPubKey, expPubKeySize);
}
