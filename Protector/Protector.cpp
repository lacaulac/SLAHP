// Protector.cpp : Définit les fonctions de la bibliothèque statique.
//
#include "framework.h"
#include "../detours.h"
#include <stdio.h>
#include <winhttp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <winternl.h>
#include <locale>
#include <codecvt>
#include <algorithm>
#include <cctype>
#include "../SignatureTool/SignUtils.h"
#include "../SignatureTool/base64.h"

#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "Wintrust.lib")

#define		PERF_MODE

//Note: This program always trusts system libraries

typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

//Function pointer type definitions
typedef NTSTATUS(NTAPI* tLdrLoadDll)(PWCHAR, ULONG*, PUNICODE_STRING, PHANDLE*);
typedef NTSTATUS(NTAPI* tNtQueryAttributesFile)(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation);
//Hook functions prototypes
NTSTATUS NTAPI hkLdrLoadDLL(PWCHAR a, ULONG* b, PUNICODE_STRING c, PHANDLE* d);
NTSTATUS NTAPI hkNtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation);
//Pointers to function address
tLdrLoadDll oLdrLoadDll = (tLdrLoadDll)DetourFindFunction("ntdll.dll", "LdrLoadDll");
tNtQueryAttributesFile oNtQueryAttributesFile = (tNtQueryAttributesFile)DetourFindFunction("ntdll.dll", "NtQueryAttributesFile");

int WcharStrPartialCmp(LPCWSTR a, LPCWSTR b/*, USHORT Length*/);
LPWSTR GetDirectoryFromFileName(LPCWSTR AbsolutePath);
LPWSTR GetPointerFileNameFromAbsolutePath(LPCWSTR AbsolutePath);
std::string ReadFileFromDisk(const char* filename);
bool WriteFileToDisk(const char* filename, std::string content);
bool FileExists(std::string path);
void RemoveCfgFiles();

DWORD __stdcall BlockAlertThread(LPVOID par);
DWORD __stdcall WaitAlertThread(LPVOID par);
void ApplyAlertDecision(PROTECTION_ACTION decision, bool isInitiator = false);
PROTECTION_ACTION GetUserDecision(LPWSTR dllName);
void advanceProtectorBlockStage();

ProtectorConfig* exposedConfig = NULL;
ProtectorInfo protectorInfo;
ProtectorGlobals protectorGlobals;
WCHAR currentExeDir[MAX_PATH * 2] = { '\0' };

LPCWSTR sysFolder64 = L"C:\\Windows\\SysWOW64";
LPCWSTR sysFolder32 = L"C:\\Windows\\System32";
LPCWSTR sysFolder = L"C:\\Windows\\System";
LPCWSTR sysWinFolder = L"C:\\Windows";

ProtectorConfig* getConfig()
{
	return exposedConfig;
}

bool InitProtector(LPCWSTR UserAgent, LPCWSTR Domain, LPCWSTR URL, bool https, bool ignoreHttpsRedFlags, LPCSTR pubKeyStr, bool enableCache, bool enableMultiProcess, bool hideFromUser)
{
	protectorInfo.Init(UserAgent, Domain, URL, https, ignoreHttpsRedFlags, pubKeyStr, enableCache, enableMultiProcess, hideFromUser);
	GetModuleFileNameW(NULL, currentExeDir, MAX_PATH * 2);
	for (size_t i = (wcslen(currentExeDir) - 1); i > 0; i--)
	{
		if(currentExeDir[i] == '\\')
		{
			currentExeDir[i] = '\0';
			break;
		}
	}
#ifndef PERF_MODE
	wprintf(L"Current folder: %ws\n", currentExeDir);
#endif

	if (exposedConfig != NULL)
		delete exposedConfig;
	exposedConfig = new ProtectorConfig();
	InitHooks(); //Must prevent basic DLLs from being loaded from anywhere else than the System directories
	//MessageBoxA(NULL, "PAUSING", "PAUSING", MB_OK);
	//GetHashes(UserAgent, Domain, URL, https, ignoreHttpsRedFlags, pubKey);

	char buffer[255] = { 0 };
	char* modName = NULL;
	GetModuleFileNameA(NULL, buffer, 254);
	for (size_t i = (strlen(buffer) - 1); i > 0; i--)
	{
		if (buffer[i] == '\\')
		{
			modName = &buffer[i + 1];
			break;
		}
	}
	if (protectorInfo.shouldUseCache)
	{
		char tmpBuffer[255] = { 0 };
		sprintf_s(tmpBuffer, 254, "%s_cachemutex", modName);
		protectorGlobals.cacheMutex = new WinMutex(tmpBuffer);
	}


	GetCfgFilesAndParse(UserAgent, Domain, URL, https, ignoreHttpsRedFlags, pubKeyStr);
	

	if (protectorInfo.shouldDoMultiProcess)
	{
		char tmpBuffer[255] = { 0 };
		sprintf_s(tmpBuffer, 254, "%s_sm", modName);
		protectorGlobals.sharedMemory = new SMManager(tmpBuffer, sizeof(ProtectorSharedActionState));
		//We check if the shared memory is initialised and initialise it if it isn't
		ProtectorSharedActionState* protectorState = protectorGlobals.sharedMemory->getPointerControl<ProtectorSharedActionState*>();
		if (protectorState->Initialization != 0xDEADBEEF)
		{
			protectorState->Initialization = 0xDEADBEEF;
			protectorState->alertAmount = 0;
		}
		protectorGlobals.sharedMemory->releasePointerControl();
		sprintf_s(tmpBuffer, 254, "%s_event", modName);
		protectorGlobals.winEvent = new WinEvent(tmpBuffer);
		protectorGlobals.waitAlertThread = CreateThread(NULL, NULL, WaitAlertThread, &protectorGlobals, NULL, NULL);
		protectorGlobals.blockStage;
	}
#ifndef PERF_MODE
	LPWSTR tmpBuf = (LPWSTR)malloc(2048);
	wsprintf(tmpBuf, L"Initialised HijackProtector:\n\tConfig URL: http%ws//%ws%ws\n\tIgnore HTTPS errors: %ws\n\tUser-Agent:%ws\n\tConfig file authenticity verification: %ws\n\n", https ? L"s:" : L":", Domain, URL, ignoreHttpsRedFlags ? L"Yes" : L"No", UserAgent, pubKeyStr == NULL ? L"No public key was provided" : L"Enabled");
	//MessageBoxW(NULL, tmpBuf, L"Protector", MB_OK);
	wprintf(L"%ws\n", tmpBuf);
	free(tmpBuf);
#endif
	return true;
}

void GetCfgFilesAndParse(LPCWSTR& UserAgent, LPCWSTR& Domain, LPCWSTR& URL, bool https, bool ignoreHttpsRedFlags, const LPCSTR& pubKeyStr)
{
	if (protectorInfo.shouldUseCache)
	{
		protectorGlobals.cacheMutex->Lock();
	}
	std::string cfgFile;

	GetAndOrStorePolicy(cfgFile, UserAgent, Domain, URL, https, ignoreHttpsRedFlags);

	if (pubKeyStr != NULL)
	{
		auto cryptoProvider = getCryptoProvider();
		LPWSTR newUrl = (LPWSTR)malloc(2048 * sizeof(wchar_t));
		swprintf_s(newUrl, MAX_PATH * sizeof(wchar_t), L"%ws.sig", URL);
		std::string pubKeyStdStr(pubKeyStr);
		auto pubKey = getPubkeyBlobFromB64(cryptoProvider, pubKeyStdStr);

		std::string cfgFileSig;
		GetOrStorePolicySignature(cfgFileSig, UserAgent, Domain, newUrl, https, ignoreHttpsRedFlags);

		//std::string cfgFileSig = GetRequest(UserAgent, Domain, newUrl, https, ignoreHttpsRedFlags, "==");

		size_t dataBufferSize = cfgFile.length() + 1;
		BYTE* dataBuffer = (BYTE*)malloc(dataBufferSize);
		const char* origCfgFileStr = cfgFile.c_str();
		//memcpy_s(dataBuffer, dataBufferSize, origCfgFileStr, dataBufferSize);
		strcpy_s((char*)dataBuffer, dataBufferSize, origCfgFileStr);
		dataBufferSize--;

		bool isValid = checkSignature(dataBuffer, dataBufferSize, cfgFileSig, pubKey, cryptoProvider);

		if (!isValid)
		{
			MessageBoxA(NULL, "The security configuration file's signature is invalid.", "Protector", MB_OK | MB_ICONERROR);
			if (FileExists("policy.cfg.sig") && protectorInfo.shouldUseCache)
			{
				RemoveCfgFiles();
				MessageBoxA(NULL, "The security policy cache has been cleared.", "Protector", MB_OK | MB_ICONINFORMATION);
			}
			ExitProcess(1);
		}
	}
	if (protectorInfo.shouldUseCache)
	{
		protectorGlobals.cacheMutex->Release();
	}
	ParseConfig(cfgFile);
}

void GetOrStorePolicySignature(std::string& cfgFileSig, const LPCWSTR& UserAgent, const LPCWSTR& Domain, const LPWSTR& newUrl, bool https, bool ignoreHttpsRedFlags)
{
	if (FileExists("policy.cfg.sig") && protectorInfo.shouldUseCache)
	{
		cfgFileSig = ReadFileFromDisk("policy.cfg.sig");
	}
	else
	{
		cfgFileSig = GetRequest(UserAgent, Domain, newUrl, https, ignoreHttpsRedFlags, "==");
		//cfgFileSig = GetRequest(UserAgent, Domain, URL, https, ignoreHttpsRedFlags, "ENDCONFIG\r\n");
		if(protectorInfo.shouldUseCache)
			WriteFileToDisk("policy.cfg.sig", cfgFileSig);
	}
}

void GetAndOrStorePolicy(std::string& cfgFile, const LPCWSTR& UserAgent, const LPCWSTR& Domain, const LPCWSTR& URL, bool https, bool ignoreHttpsRedFlags)
{
	if (FileExists("policy.cfg") && protectorInfo.shouldUseCache)
	{
		cfgFile = ReadFileFromDisk("policy.cfg");
	}
	else
	{
		cfgFile = GetRequest(UserAgent, Domain, URL, https, ignoreHttpsRedFlags, "ENDCONFIG\r\n");
		if (protectorInfo.shouldUseCache)
			WriteFileToDisk("policy.cfg", cfgFile);
	}
}

void InitHooks()
{
	//Place the hooks
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	LoadLibraryA("ntdll.dll");
	LoadLibraryA("KernelBase.dll");
	DetourAttach(&(PVOID&)oLdrLoadDll, hkLdrLoadDLL);
	DetourAttach(&(PVOID&)oNtQueryAttributesFile, hkNtQueryAttributesFile);
	DetourTransactionCommit();
}

//From https://slaystudy.com/c-split-string-by-space-into-vector/
void SplitString(std::string s, char separator, std::vector<std::string>* v) {

	std::string temp = "";
	for (int i = 0; i < s.length(); ++i) {

		if (s[i] == separator) {
			v->push_back(temp);
			temp = "";
		}
		else {
			temp.push_back(s[i]);
		}

	}
	v->push_back(temp);
}

/// <summary>
/// Computes a hash from input data and its length
/// </summary>
/// <param name="data">The data that needs to be hashed</param>
/// <param name="dataLength">The length of the data</param>
/// <returns>A pointer to an allocated char[65] buffer containing the SHA256 hash under a string representation</returns>
/// <remarks>Do not forget to free the returned buffer after use</remarks>
char* ComputeHash(const char* data, size_t dataLength)
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE* pbHash = NULL;
	DWORD dwHashLen;

	BYTE* pbBuffer = NULL;
	DWORD dwCount;

	if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) {
		auto lastError = GetLastError();
		if (lastError == NTE_BAD_KEYSET) {
			if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
				MessageBoxA(NULL, "Couldn't acquire cryptcontext.", "HijackProtector", MB_OK | MB_ICONERROR);
				return NULL;
			}
		}
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		MessageBoxA(NULL, "Couldn't create a hash creator.", "HijackProtector", MB_OK | MB_ICONERROR);
		return NULL;
	}

	pbBuffer = (BYTE*)malloc(dataLength + 1);
	if (pbBuffer == NULL)
	{
		MessageBoxA(NULL, "Couldn't allocate buffer for hash calculation.", "HijackProtector", MB_OK | MB_ICONERROR);
		return NULL;
	}

	memset(pbBuffer, 0, dataLength + 1);

	memcpy(pbBuffer, data, dataLength);

	if (!CryptHashData(hHash, pbBuffer, (DWORD)dataLength, 0)) {
		MessageBoxA(NULL, "Couldn't calculate the hash.", "HijackProtector", MB_OK | MB_ICONERROR);
		free(pbBuffer);
		return NULL;
	}

	dwCount = sizeof(DWORD);
	if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&dwHashLen, &dwCount, 0)) {
		MessageBoxA(NULL, "Couldn't get the hash length.", "HijackProtector", MB_OK | MB_ICONERROR);
		free(pbBuffer);
		return NULL;
	}
	if ((pbHash = (unsigned char*)malloc(dwHashLen)) == NULL) {
		MessageBoxA(NULL, "Couldn't allocate a raw hash buffer.", "HijackProtector", MB_OK | MB_ICONERROR);
		free(pbBuffer);
		return NULL;
	}

	memset(pbHash, 0, dwHashLen);

	if (!CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashLen, 0)) {
		MessageBoxA(NULL, "Couldn't get the hash value.", "HijackProtector", MB_OK | MB_ICONERROR);
		free(pbBuffer); 
		free(pbHash);
		return NULL;
	}

	char* finalHashBuffer = (char*)malloc(64 + 1); //Store our SHA256 hash as a string

	if (finalHashBuffer == NULL)
	{
		MessageBoxA(NULL, "Couldn't allocate the return buffer for hash calculation.", "HijackProtector", MB_OK | MB_ICONERROR);
		free(pbHash);
		free(pbBuffer);
	}

	for (int i = 0; i < 32; i++)
	{
		sprintf_s(&(finalHashBuffer[i*2]), 65 - (i * 2), "%02x", (BYTE)pbHash[i]);
	}

	free(pbHash);
	free(pbBuffer);

	if (hHash) CryptDestroyHash(hHash);
	if (hProv) CryptReleaseContext(hProv, 0);

	return finalHashBuffer;
}

std::string GetRequest(LPCWSTR UserAgent, LPCWSTR Domain, LPCWSTR URL, bool https, bool ignoreHttpsRedFlags, const char* ending)
{
	BOOL bResults = FALSE;
	HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

	hSession = WinHttpOpen(UserAgent,
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession)
		hConnect = WinHttpConnect(hSession, Domain,
			INTERNET_DEFAULT_HTTPS_PORT, 0);
	else
	{
		MessageBoxA(NULL, "Couldn't open the HTTP connection.", "HijackProtector", MB_OK | MB_ICONERROR);
		ExitProcess(1);
	}

	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"GET", URL,
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			(https ? WINHTTP_FLAG_SECURE : 0));
	else
	{
		MessageBoxA(NULL, "Couldn't open the HTTP session.", "HijackProtector", MB_OK | MB_ICONERROR);
		ExitProcess(1);
	}

	if (hRequest)
	{
		DWORD dwFlags =
			ignoreHttpsRedFlags ? (SECURITY_FLAG_IGNORE_UNKNOWN_CA |
				SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
				SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
				SECURITY_FLAG_IGNORE_CERT_DATE_INVALID) : 0;
		WinHttpSetOption(
			hRequest,
			WINHTTP_OPTION_SECURITY_FLAGS,
			&dwFlags,
			sizeof(dwFlags));

		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS,
			0, WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);
	}
	else
	{
		MessageBoxA(NULL, "Couldn't create an HTTP request.", "HijackProtector", MB_OK | MB_ICONERROR);
		ExitProcess(1);
	}
	if (bResults)
	{
		if (WinHttpReceiveResponse(hRequest, NULL))
		{
			//TODO Crash entre 2000 et 3000 hashs (fichiers de config de plus de 200Ko)
			DWORD dwDownloaded, dwSize;
			char* buf = NULL;
			size_t writePos = 0;
			std::string cfgStr("");
			do
			{
				if (!WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize)
					break;
				if (buf == NULL)
				{
					buf = (char*)malloc(dwSize + 1);
					if (!buf)
					{
						MessageBoxA(NULL, "Couldn't allocate a new buffer for HTTP data.", "HijackProtector", MB_OK | MB_ICONERROR);
						ExitProcess(1);
					}
				}
				if (WinHttpReadData(hRequest, (LPVOID)(buf + writePos), dwSize, &dwDownloaded))
				{
					//fwrite(buf, sizeof(char), dwSize, stdout);
					if (!dwDownloaded || strstr(buf, ending) != NULL)
					{
						*(char*)(strstr(buf, ending) + strlen(ending)) = '\0';
						cfgStr.append(buf);
						free(buf);
						buf = NULL;
						break;
					}
					cfgStr.append(buf);
					free(buf);
					buf = NULL;
				}
			} while (dwSize > 0);
			if (hRequest)
				WinHttpCloseHandle(hRequest);
			if (hConnect)
				WinHttpCloseHandle(hConnect);
			if (hSession)
				WinHttpCloseHandle(hSession);
			return cfgStr;
		}
		else
		{
			MessageBoxA(NULL, "Got no response.", "HijackProtector", MB_OK | MB_ICONERROR);
			return std::string("Error");
		}
	}
	else
	{
		if (hRequest)
			WinHttpCloseHandle(hRequest);
		if (hConnect)
			WinHttpCloseHandle(hConnect);
		if (hSession)
			WinHttpCloseHandle(hSession);
		char msgBuffer[512] = { '\0' };
		sprintf_s(msgBuffer, 511, "Error %d has occurred.\n", GetLastError());
		MessageBoxA(NULL, msgBuffer, "Protector", MB_OK | MB_ICONERROR);
		return std::string("Error");
	}
}

void ParseConfig(std::string cfgStr)
{
#ifndef PERF_MODE_
	printf("PID[%u] parsing config file...\n", GetCurrentProcessId());
#endif
	exposedConfig->clear();
	std::vector<std::string>* lines = new std::vector<std::string>();
	SplitString(cfgStr, '\n', lines);
	for (size_t i = 0; i < lines->size(); i++)
	{
		if (i == 0) //allowunspecified
		{
			exposedConfig->allowUnspecified = lines->at(i).compare("allowunspecified:yes\r") == 0;
		}
		else if (i == 1) //unspecifiedhastobesigned
		{
			exposedConfig->signatureAllowsBypass = lines->at(i).compare("signatureallowsbypass:yes\r") == 0;
		}
		else if (i == 2) //unspecifiedcantbeinlocaldirectory
		{
			exposedConfig->unspecifiedCantBeInLocalDirectory = lines->at(i).compare("unspecifiedcantbeinlocaldirectory:yes\r") == 0;
		}
		else if (lines->at(i).compare("ENDCONFIG\r") == 0)
		{
			break;
		}
		else
		{
			std::vector<std::string> parts;
			SplitString(lines->at(i), ':', &parts);
			std::vector<std::string> hashes;
			std::string dllName = parts.at(0);
			std::transform(dllName.begin(), dllName.end(), dllName.begin(),
				[](unsigned char c) { return std::tolower(c); });
#ifndef PERF_MODE
			printf("File: %s\n", dllName.c_str());
#endif
			SplitString(parts.at(1), ',', &hashes);
#ifndef PERF_MODE
			printf("Hash amount: %u\n", hashes.size());
			for (size_t i2 = 0; i2 < hashes.size(); i2++)
			{
				printf("\t%s\n", hashes.at(i2).c_str());
			}
#endif
			exposedConfig->hashes.insert(std::pair<std::string, std::vector<std::string>>(dllName, hashes));
		}
	}
	delete lines;
	exposedConfig->isInitialised = true;
}

BOOL VerifyEmbeddedSignature(LPCWSTR fullPathToFile) //https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file?redirectedfrom=MSDN
{
	LONG lStatus;
	DWORD dwLastError;

	// Initialize the WINTRUST_FILE_INFO structure.

	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = fullPathToFile;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	/*
	WVTPolicyGUID specifies the policy to apply on the file
	WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

	1) The certificate used to sign the file chains up to a root
	certificate located in the trusted root certificate store. This
	implies that the identity of the publisher has been verified by
	a certification authority.

	2) In cases where user interface is displayed (which this example
	does not do), WinVerifyTrust will check for whether the
	end entity certificate is stored in the trusted publisher store,
	implying that the user trusts content from this publisher.

	3) The end entity certificate has sufficient permission to sign
	code, as indicated by the presence of a code signing EKU or no
	EKU.
	*/

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	// Initialize the WinVerifyTrust input data structure.

	// Default all fields to 0.
	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);

	// Use default code signing EKU.
	WinTrustData.pPolicyCallbackData = NULL;

	// No data to pass to SIP.
	WinTrustData.pSIPClientData = NULL;

	// Disable WVT UI.
	WinTrustData.dwUIChoice = WTD_UI_NONE;

	// No revocation checking.
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

	// Verify an embedded signature on a file.
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

	// Verify action.
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	// Verification sets this value.
	WinTrustData.hWVTStateData = NULL;

	// Not used.
	WinTrustData.pwszURLReference = NULL;

	// This is not applicable if there is no UI because it changes 
	// the UI to accommodate running applications instead of 
	// installing applications.
	WinTrustData.dwUIContext = 0;

	// Set pFile.
	WinTrustData.pFile = &FileData;

	//Only use local cache for revocations
	WinTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_HASH_ONLY_FLAG; //TODO Remove WTD_HASH_ONLY_FLAG => It allows self-signed code signature certificates (useful for performance tests, same speed)

	// WinVerifyTrust verifies signatures as specified by the GUID 
	// and Wintrust_Data.
	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	switch (lStatus)
	{
	case ERROR_SUCCESS:
		/*
		Signed file:
			- Hash that represents the subject is trusted.

			- Trusted publisher without any verification errors.

			- UI was disabled in dwUIChoice. No publisher or
				time stamp chain errors.

			- UI was enabled in dwUIChoice and the user clicked
				"Yes" when asked to install and run the signed
				subject.
		*/
#ifndef PERF_MODE
		wprintf_s(L"The file \"%s\" is signed and the signature "
			L"was verified.\n",
			fullPathToFile);
#endif
		return true;
		break;

	case TRUST_E_NOSIGNATURE:
		// The file was not signed or had a signature 
		// that was not valid.

		// Get the reason for no signature.
		dwLastError = GetLastError();
		if (TRUST_E_NOSIGNATURE == dwLastError ||
			TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
			TRUST_E_PROVIDER_UNKNOWN == dwLastError)
		{
			// The file was not signed.
#ifndef PERF_MODE
			wprintf_s(L"The file \"%s\" is not signed.\n",
				fullPathToFile);
#endif
		}
		else
		{
			// The signature was not valid or there was an error 
			// opening the file.
#ifndef PERF_MODE
			wprintf_s(L"An unknown error occurred trying to "
				L"verify the signature of the \"%s\" file.\n",
				fullPathToFile);
#endif
		}
		return false;

		break;

	case TRUST_E_EXPLICIT_DISTRUST:
		// The hash that represents the subject or the publisher 
		// is not allowed by the admin or user.
#ifndef PERF_MODE
		wprintf_s(L"The signature is present, but specifically "
			L"disallowed.\n");
#endif
		return false;
		break;

	case TRUST_E_SUBJECT_NOT_TRUSTED:
		// The user clicked "No" when asked to install and run.
#ifndef PERF_MODE
		wprintf_s(L"The signature is present, but not "
			L"trusted.\n");
#endif
		return false;
		break;

	case CRYPT_E_SECURITY_SETTINGS:
		/*
		The hash that represents the subject or the publisher
		was not explicitly trusted by the admin and the
		admin policy has disabled user trust. No signature,
		publisher or time stamp errors.
		*/
#ifndef PERF_MODE
		wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
			L"representing the subject or the publisher wasn't "
			L"explicitly trusted by the admin and admin policy "
			L"has disabled user trust. No signature, publisher "
			L"or timestamp errors.\n");
#endif
		break;
		return false;
	default:
		// The UI was disabled in dwUIChoice or the admin policy 
		// has disabled user trust. lStatus contains the 
		// publisher or time stamp chain error.
#ifndef PERF_MODE
		wprintf_s(L"Error is: 0x%x.\n",
			lStatus);
#endif
		return false;
		break;
	}

	// Any hWVTStateData must be released by a call with close.
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	return true;
}

//Make a note of the DLLs that are being loaded for the NtQueryAttributesFile hook to work correctly
NTSTATUS NTAPI hkLdrLoadDLL(PWCHAR a, ULONG* b, PUNICODE_STRING c, PHANDLE* d)
{
	//std::wstring tmpWStr(c->Buffer);
	//currentlyLoadingLibraries->insert(tmpWStr);

	NTSTATUS test = oLdrLoadDll(a, b, c, d);
	/* Return value to look for
		0xC0000135

		STATUS_DLL_NOT_FOUND

		{Unable To Locate Component} This application has failed to start because %hs was not found. Reinstalling the application might fix this problem.
		Inspecter NtCreateFile ?
	*/

	//currentlyLoadingLibraries->erase(tmpWStr);
	return test;
}

//Check where the system tries to load the DLL from and report to the controller. Only shows one call per DLL that was passed to LdrLoadDll
NTSTATUS NTAPI hkNtQueryAttributesFile(POBJECT_ATTRIBUTES a, PFILE_BASIC_INFORMATION b)
{
	if (wcsstr(a->ObjectName->Buffer + 4, L".dll") == NULL && wcsstr(a->ObjectName->Buffer + 4, L".DLL") == NULL)
	{
		return oNtQueryAttributesFile(a, b);
	}
	NTSTATUS tmp = 0;
	//wprintf(L"NtQueryAttributesFile(%ws, ?);\n", a->ObjectName->Buffer);
	if (!exposedConfig->isInitialised) //If the config isn't initialised, prevent everything from local directory
	{ // (LPWSTR(((char*)a->ObjectName->Buffer) + 0))
		LPWSTR dllDirectory = GetDirectoryFromFileName(a->ObjectName->Buffer + 4);
		if (WcharStrPartialCmp(dllDirectory, currentExeDir) == 0/*, wcslen(currentExeDir)) == 0*/) //If this is the same directory
		{
			//Prevent loading
#ifndef PERF_MODE
			printf("Prevented loading from app directory before initialisation\n");
#endif
			tmp =  0xC0000034;
		}
		else
		{
			tmp = oNtQueryAttributesFile(a, b);
		}
		delete dllDirectory;
	}
	else
	{
		FILE_BASIC_INFORMATION outInfo;
		NTSTATUS tmpStatus = oNtQueryAttributesFile(a, &outInfo);
		if (tmpStatus == 0) //If the file could be loaded
		{
			bool isAuthorised = false;
			bool isKnownDll = false;
			LPWSTR dllDirectory = GetDirectoryFromFileName(a->ObjectName->Buffer + 4);
			if (WcharStrPartialCmp(dllDirectory, sysFolder64) == 0 || WcharStrPartialCmp(dllDirectory, sysFolder32) == 0 || WcharStrPartialCmp(dllDirectory, sysFolder) == 0 || WcharStrPartialCmp(dllDirectory, sysWinFolder) == 0) //System files are always allowed to be loaded
			{
				isAuthorised = true;
			}
			else
			{
				//Convert name to Cpp String
				LPWSTR dllName = GetPointerFileNameFromAbsolutePath(a->ObjectName->Buffer);
				using convert_typeX = std::codecvt_utf8<wchar_t>;
				std::wstring_convert<convert_typeX, wchar_t> converterX;
				std::string stringDllName = converterX.to_bytes(std::wstring(dllName));

				std::transform(stringDllName.begin(), stringDllName.end(), stringDllName.begin(),
					[](unsigned char c) { return std::tolower(c); });
#ifndef PERF_MODE
				printf("Looking for %s\n", stringDllName.c_str());
#endif

				//If found
				if (exposedConfig->hashes.count(stringDllName))
				{
					isKnownDll = true;
					//Read the file
					HANDLE dllHandle = CreateFileW(a->ObjectName->Buffer + 4, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); // https://docs.microsoft.com/en-us/windows/win32/fileio/opening-a-file-for-reading-or-writing
					DWORD fileSize = GetFileSize(dllHandle, NULL);
					BYTE* buffer = (BYTE*)malloc(fileSize);
					ReadFile(dllHandle, buffer, fileSize, NULL, NULL);
					CloseHandle(dllHandle);
					//Calculate hash
					std::string dllHash = std::string(ComputeHash((const char*)buffer, fileSize));
					free(buffer);
					//Compare to known hashes
					for (int i = 0; i < exposedConfig->hashes[stringDllName].size(); i++)
					{
						if (exposedConfig->hashes[stringDllName][i].compare(dllHash) == 0 || exposedConfig->hashes[stringDllName][i].compare(dllHash + "\r") == 0)
						{
							isAuthorised = true;
#ifndef PERF_MODE
							printf("\tAllowed loading whitelisted DLL!\n");
#endif // !PERF_MODE
							break;
						}
					}
				}
			}

			if (!isAuthorised)
			{
				//If it still isn't authorised, check other config options
				
				//Unspecified territory
				//printf("isAuthorised: %s\nallowUnspecified: %s\nisKnownDll: %s\n", isAuthorised ? "true" : "false", exposedConfig->allowUnspecified ? "true" : "false", isKnownDll ? "true" : "false");
				if (exposedConfig->allowUnspecified && !isKnownDll) //Check if the DLL is really unspecified and if unspecified DLLs are allowed
				{
					if (WcharStrPartialCmp(dllDirectory, currentExeDir) == 0) //If the DLL is not in the list and we allow local directory loading
					{
						if (exposedConfig->unspecifiedCantBeInLocalDirectory)
						{
							isAuthorised = false;
#ifndef PERF_MODE
							printf("\tBlocked the loading because unspecified files can't be in local directories\n");
#endif // !PERF_MODE
						}
						else
						{
#ifndef PERF_MODE
							printf("Allowed the loading because unspecified DLLs can be in the local directory!\n");
#endif // !PERF_MODE
							isAuthorised = true;
						}
					}
					else
					{
						isAuthorised = true;
					}
				}
				if (!isAuthorised && exposedConfig->signatureAllowsBypass)
				{
					//Check signature here
					bool isSigned = VerifyEmbeddedSignature(a->ObjectName->Buffer + 4);
					isAuthorised = isSigned;
				}
				
			}
			delete dllDirectory;

			if (isAuthorised) //If allowed
			{
				memcpy(b, &outInfo, sizeof(FILE_BASIC_INFORMATION));
				tmp = tmpStatus;
			}
			else
			{
#ifndef PERF_MODE
				printf("Prevented loading unauthorized DLL\n");
#endif // !PERF_MODE

				tmp = 0xC0000034;
			}
			if (tmp == 0xC0000034 && !exposedConfig->rt_DllLoadBlockOccurred)
			{
				exposedConfig->rt_DllLoadBlockOccurred = true;

				//We copy the DLL's name
				LPWSTR tmpStr = (LPWSTR)calloc(1, lstrlenW(a->ObjectName->Buffer + 4) * sizeof(wchar_t) + 2);
				memcpy(tmpStr, a->ObjectName->Buffer + 4, lstrlenW(a->ObjectName->Buffer + 4) * sizeof(wchar_t) + 2);

				if (!protectorInfo.hideFromUser)
				{
					if (protectorInfo.shouldDoMultiProcess)
					{
						//Not using a thread anymore so that the system can retry loading the DLL
						BlockAlertThread(tmpStr);
					}
					else
					{
						auto decision = GetUserDecision(tmpStr);
						free(tmpStr);
						ApplyAlertDecision(decision);
					}
				}
				else
				{
					if (protectorInfo.shouldDoMultiProcess)
					{
						BlockAlertThread(tmpStr);
					}
					else
					{
						advanceProtectorBlockStage();
					}
				}
				//MessageBoxA(NULL, "An unauthorised DLL loading was blocked.\nClick Continue to download a potentially newer version of the security policy. If this doesn't solve your issue, this message could indicate an active attack.\nClick on Try to resume execution\nClick on Cancel to terminate the process", "Protector", MB_ICONEXCLAMATION | MB_CANCELTRYCONTINUE | MB_TASKMODAL);
			}
		}
		else
		{
			tmp = tmpStatus;
		}
	}
	//printf("\t=>%p\n", tmp);
	
#ifndef PERF_MODE
	if (tmp == 0xC0000034)
		wprintf(L"Blocked the loading of %ws\n", a->ObjectName->Buffer + 4);
	else
		wprintf(L"Allowed the loading of %ws : %08x\n", a->ObjectName->Buffer + 4, tmp);
#endif
	return tmp;
}

int WcharStrPartialCmp(LPCWSTR a, LPCWSTR b)
{
	//wprintf(L"Comparing:\n\t%ws\n\t%ws\n\n", a, b);
	return _wcsicmp(a, b);
}

LPWSTR GetDirectoryFromFileName(LPCWSTR AbsolutePath)
{
	wchar_t* clone = new wchar_t[wcslen(AbsolutePath) + 1];
	wcscpy_s(clone, wcslen(AbsolutePath) + 1, AbsolutePath);
	for (size_t i = (wcslen(clone) - 1); i > 0; i--)
	{
		if (clone[i] == '\\')
		{
			clone[i] = '\0';
			break;
		}
	}
	return clone;
}

LPWSTR GetPointerFileNameFromAbsolutePath(LPCWSTR AbsolutePath)
{
	for (size_t i = (wcslen(AbsolutePath) - 1); i > 0; i--)
	{
		if (AbsolutePath[i] == '\\')
		{
			return (LPWSTR)&(AbsolutePath[i + 1]);
		}
	}
	return NULL;
}

std::string ReadFileFromDisk(const char* filename)
{
	FILE* tmpFile = NULL;
	fopen_s(&tmpFile, filename, "rb");
	fseek(tmpFile, 0, SEEK_END);
	long fileContentSize = ftell(tmpFile);
	fseek(tmpFile, 0, SEEK_SET);
	BYTE* fileContent = (BYTE*)malloc(fileContentSize + 1);
	fread(fileContent, fileContentSize, 1, tmpFile);
	fclose(tmpFile);
	fileContent[fileContentSize] = '\0';
	std::string result((char*)fileContent);
	free(fileContent);
	return result;
}

bool WriteFileToDisk(const char* filename, std::string content)
{
	FILE* tmpFile = NULL;
	fopen_s(&tmpFile, filename, "wb");
	size_t strSize = content.size();
	const char* str = content.c_str();
	fwrite(str, strSize, 1, tmpFile);
	fclose(tmpFile);
	return true;
}

bool FileExists(std::string path)
{
	struct stat buff;
	return stat(path.c_str(), &buff) == 0;
}

void RemoveCfgFiles()
{
	remove("policy.cfg");
	remove("policy.cfg.sig");
}

DWORD __stdcall BlockAlertThread(LPVOID par)
{
	//auto pausedThreads = ThreadManager::PauseEveryOtherThread();

	SuspendThread(protectorGlobals.waitAlertThread);

	auto state = protectorGlobals.sharedMemory->getPointerControl<ProtectorSharedActionState*>();

	protectorGlobals.winEvent->trigger(NULL);

	LPWSTR dllName = (LPWSTR)par;
	PROTECTION_ACTION decision = PROTECTION_ACTION::IGNORE_ALERT;
	if (!protectorInfo.hideFromUser)
	{
		decision = GetUserDecision(dllName);
	}
	else
	{
		advanceProtectorBlockStage();
		decision = PROTECTION_ACTION::RELOAD;
	}
	free(dllName);
	state->ProtectionAction = decision;
	protectorGlobals.cacheMutex->Lock();
	protectorGlobals.sharedMemory->releasePointerControl();
	ApplyAlertDecision(decision, true); //Possible race condition
	ResumeThread(protectorGlobals.waitAlertThread);
	//ThreadManager::ResumeThreads(pausedThreads);
	return 0;
}

DWORD __stdcall WaitAlertThread(LPVOID par)
{
	auto globals = reinterpret_cast<ProtectorGlobals*>(par);
	while (true)
	{
		globals->winEvent->wait(NULL);
		Sleep(100);
		auto pausedThreads = ThreadManager::PauseEveryOtherThread();
		auto state = globals->sharedMemory->getPointerControl<ProtectorSharedActionState*>();
		auto decision = state->ProtectionAction;
		globals->sharedMemory->releasePointerControl();
		ThreadManager::ResumeThreads(pausedThreads);
		ApplyAlertDecision(decision);
	}
	return 0;
}

void ApplyAlertDecision(PROTECTION_ACTION decision, bool isInitiator)
{
	switch (decision)
	{
	case PROTECTION_ACTION::IGNORE_ALERT:
		break;
	case PROTECTION_ACTION::RELOAD:
		if (protectorInfo.shouldUseCache && isInitiator)
		{
			RemoveCfgFiles();
			protectorGlobals.cacheMutex->Release();
		}
		GetCfgFilesAndParse(protectorInfo.UserAgent, protectorInfo.Domain, protectorInfo.URL, protectorInfo.https, protectorInfo.ignoreHttpsRedFlags, protectorInfo.pubKeyStr);
		break;
	case PROTECTION_ACTION::QUIT:
		TerminateProcess(GetCurrentProcess(), 1337);
		break;
	}
}

PROTECTION_ACTION GetUserDecision(LPWSTR dllName)
{
	wchar_t buffer[2048] = { 0 };
	wsprintfW(buffer, L"An unauthorised DLL loading was blocked.\n\tPath: %ws\nIgnore to resume execution\nRetry to download and apply a fresh policy. If this does not solve your problem, your computer could be actively under attack\nAbort to terminate the current process.", dllName);
	int res = MessageBoxW(NULL, buffer, L"Protector", MB_ABORTRETRYIGNORE | MB_ICONEXCLAMATION);
	PROTECTION_ACTION decision = PROTECTION_ACTION::QUIT;
	switch (res)
	{
	case IDIGNORE:
		decision = PROTECTION_ACTION::IGNORE_ALERT;
		break;
	case IDRETRY:
		decision = PROTECTION_ACTION::RELOAD;
		break;
	case IDABORT:
		decision = PROTECTION_ACTION::QUIT;
		break;
	}
	return decision;
}

void advanceProtectorBlockStage()
{
	switch (protectorGlobals.blockStage)
	{
	case ProtectorBlockStage::CLEAR:
		protectorGlobals.blockStage = ProtectorBlockStage::ONEBLOCK;
		ApplyAlertDecision(PROTECTION_ACTION::RELOAD);
		break;
	case ProtectorBlockStage::ONEBLOCK:
		protectorGlobals.blockStage = ProtectorBlockStage::TWOBLOCKS;
		ApplyAlertDecision(PROTECTION_ACTION::RELOAD);
		break;
	case ProtectorBlockStage::TWOBLOCKS:
		protectorGlobals.blockStage = ProtectorBlockStage::ALERTED;
		MessageBoxA(NULL, "The current program tried to load invalid DLLs at least three times. This could stem from either a genuinely invalid file (corrupt data, modding, etc.) or a computer attack. Concerning the latter, there's no immediate danger as the loading of these invalid DLLs has been blocked, but we still recommend running a system-wide scan.", "Protector", MB_ICONWARNING);
		break;
	case ProtectorBlockStage::ALERTED:
		break;
	}
}