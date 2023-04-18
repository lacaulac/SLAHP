#pragma once
#include <map>
#include <vector>
#include <string>
#include <Windows.h>
#include "WinEvent.h"
#include "SMManager.h"
#include "ThreadManager.h"
#include "NotificationSystem.h"


void InitHooks();
bool InitProtector(LPCWSTR UserAgent, LPCWSTR Domain, LPCWSTR URL, bool https, bool ignoreHttpsRedFlags, LPCSTR pubKeyStr, bool enableCache = true, bool enableMultiProcess = false, bool hideFromUser = false);
void GetCfgFilesAndParse(LPCWSTR& UserAgent, LPCWSTR& Domain, LPCWSTR& URL, bool https, bool ignoreHttpsRedFlags, const LPCSTR& pubKeyStr);
void GetOrStorePolicySignature(std::string& cfgFileSig, const LPCWSTR& UserAgent, const LPCWSTR& Domain, const LPWSTR& newUrl, bool https, bool ignoreHttpsRedFlags);
void GetAndOrStorePolicy(std::string& cfgFile, const LPCWSTR& UserAgent, const LPCWSTR& Domain, const LPCWSTR& URL, bool https, bool ignoreHttpsRedFlags);
char* ComputeHash(const char* data, size_t dataLength);
std::string GetRequest(LPCWSTR UserAgent, LPCWSTR Domain, LPCWSTR URL, bool https, bool ignoreHttpsRedFlags, const char* ending);
//void GetHashes();
void ParseConfig(std::string cfgStr);

typedef struct _ProtectorConfig {
	bool isInitialised = false;
	bool allowUnspecified = true;
	bool signatureAllowsBypass = true;
	bool unspecifiedCantBeInLocalDirectory = false;
	bool rt_DllLoadBlockOccurred = false;
	std::map<std::string, std::vector<std::string>> hashes;

	void clear()
	{
		isInitialised = false;
		allowUnspecified = true;
		signatureAllowsBypass = true;
		unspecifiedCantBeInLocalDirectory = false;
		rt_DllLoadBlockOccurred = false;
		hashes.clear();
	}
} ProtectorConfig;

typedef struct _ProtectorInfo {
public:
	LPCWSTR UserAgent;
	LPCWSTR Domain;
	LPCWSTR URL;
	bool https;
	bool ignoreHttpsRedFlags;
	LPCSTR pubKeyStr;
	bool shouldUseCache;
	bool shouldDoMultiProcess;
	bool hideFromUser;

	void Init(LPCWSTR UserAgent, LPCWSTR Domain, LPCWSTR URL, bool https, bool ignoreHttpsRedFlags, LPCSTR pubKeyStr)
	{
		this->Init(UserAgent, Domain, URL, https, ignoreHttpsRedFlags, pubKeyStr, true, false, false);
	}

	void Init(LPCWSTR UserAgent, LPCWSTR Domain, LPCWSTR URL, bool https, bool ignoreHttpsRedFlags, LPCSTR pubKeyStr, bool shouldUseCache, bool shouldDoMultiProcess, bool hideFromUser)
	{
		void* bufferPointer = NULL;
		size_t bufferSize = 0;

		bufferSize = ((size_t)lstrlenW(UserAgent) + 1) * sizeof(wchar_t);
		bufferPointer = malloc(bufferSize);
		memcpy(bufferPointer, UserAgent, bufferSize);
		this->UserAgent = (LPCWSTR)bufferPointer;

		bufferSize = ((size_t)lstrlenW(Domain) + 1) * sizeof(wchar_t);
		bufferPointer = malloc(bufferSize);
		memcpy(bufferPointer, Domain, bufferSize);
		this->Domain = (LPCWSTR)bufferPointer;

		bufferSize = ((size_t)lstrlenW(URL) + 1) * sizeof(wchar_t);
		bufferPointer = malloc(bufferSize);
		memcpy(bufferPointer, URL, bufferSize);
		this->URL = (LPCWSTR)bufferPointer;

		this->https = https;

		this->ignoreHttpsRedFlags = ignoreHttpsRedFlags;

		if (pubKeyStr != NULL)
		{
			bufferSize = (strlen(pubKeyStr) + (int)1) * sizeof(char);
			bufferPointer = malloc(bufferSize);
			memcpy(bufferPointer, pubKeyStr, bufferSize);
			this->pubKeyStr = (LPCSTR)bufferPointer;
		}
		else
			this->pubKeyStr = NULL;

		this->shouldUseCache = shouldUseCache;
		this->shouldDoMultiProcess = shouldDoMultiProcess;
		this->hideFromUser = hideFromUser;
	}

	void Release()
	{
		free((void*)this->UserAgent);
		free((void*)this->Domain);
		free((void*)this->URL);
		free((void*)this->pubKeyStr);
	}
} ProtectorInfo;

enum class ProtectorBlockStage {
	CLEAR,
	ONEBLOCK,
	TWOBLOCKS,
	ALERTED
};

typedef struct ProtectorGlobals {
	WinEvent* winEvent;
	SMManager* sharedMemory;
	WinMutex* cacheMutex;
	HANDLE waitAlertThread;
	ProtectorBlockStage blockStage;
};