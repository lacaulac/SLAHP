#pragma once

#pragma comment(lib, "BCrypt.lib")

#include <stdio.h>
#include <windows.h>
#include <bcrypt.h>
#include "base64.h"

void handleError(const char* err);
void handleNtError(const char* err, NTSTATUS val);
void hexdump(void* ptr, int buflen);

BCRYPT_ALG_HANDLE getCryptoProvider();
BCRYPT_KEY_HANDLE generateKeys(BCRYPT_ALG_HANDLE cryptoProvider);
BCRYPT_KEY_HANDLE getPrivkeyBlobFromB64(BCRYPT_ALG_HANDLE cryptoProvider, std::string b64data);
BCRYPT_KEY_HANDLE getPubkeyBlobFromB64(BCRYPT_ALG_HANDLE cryptoProvider, std::string b64data);
std::string hashToB64(BYTE* data, ULONG dataLength);
std::string signData(BYTE* data, ULONG dataLength, BCRYPT_KEY_HANDLE privKey, BCRYPT_ALG_HANDLE cryptoProvider);
bool checkSignature(BYTE* data, ULONG dataLength, std::string dataSignature, BCRYPT_KEY_HANDLE pubKey, BCRYPT_ALG_HANDLE cryptoProvider);
std::string getB64Privkey(BCRYPT_KEY_HANDLE privKey);
std::string getB64Pubkey(BCRYPT_KEY_HANDLE pubKey);