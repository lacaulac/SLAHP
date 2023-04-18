#pragma once
#include <Windows.h>
#include <stdio.h>
#include "WinMutex.h"

//Faiblesses solution :
// Tout le monde peut utiliser le mutex et la mémoire partagée

class SMManager
{
public:
	SMManager(const char* name, size_t size);
	template<typename T> T getPointerControl();
	void releasePointerControl();
private:
	HANDLE hMapFile = NULL;
	WinMutex* mutex = NULL;
	void* mappedMemory = NULL;
};

template<typename T>
inline T SMManager::getPointerControl()
{
	mutex->Lock();
	return reinterpret_cast<T>(mappedMemory);
}
