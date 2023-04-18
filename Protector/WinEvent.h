#pragma once
#include <Windows.h>
#include <stdio.h>
#include <aclapi.h>

//Faiblesses solution :
// Tout le monde peut utiliser l'évenement
// Fonction PulseEvent dépréciée (ne semble pas poser de souci)

class WinEvent
{
public:
	WinEvent(const char* eventName);
	void trigger(DWORD waitTime);
	void wait(DWORD waitTime);
private:
	HANDLE hEvent = NULL;
};

