// DumbImporter.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include "../Protector/framework.h"
#include <Windows.h>
#include "DumbImporter.h"

void spawnChild(char* cmdLine)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
}

int main(int argc, char** argv)
{
    bool useMultiProcess = false;
    bool createChild = false;
    bool isChildProcess = false;
    if (argc == 3)
    {
        useMultiProcess = true;
        createChild = true;
    }
    if (argc == 2)
    {
        useMultiProcess = true;
        isChildProcess = true;
    }

    InitProtector(L"HijackProtector", L"lacaulac.ovh", L"/stage3a/test.cfg", true, true, NULL, false, useMultiProcess, false);
    //InitProtector();

    if (createChild)
    {
        Sleep(5000);
        spawnChild((char*)".\\DumbImporter.exe child");
    }


    if (isChildProcess)
    {
        //Create security error
        LoadLibraryA("invalid.dll");
        printf("Child : Finished trying to load invalid.dll\n");
        Sleep(6000);
        LoadLibraryA("invalid.dll");
    }
    else
    {
        Sleep(20000);
    }

    /*TryAndLoadLib();
    Sleep(5000);
    TryAndLoadLib();
    Sleep(5000);*/
}

void TryAndLoadLib()
{
    HMODULE tmp = LoadLibraryA("Displaymessagebox.dll");
    if (tmp == NULL)
    {
        printf("Couldn't load DLL\n");
        /*DWORD error = GetLastError();
        printf("Error: %ud\n\n", error);*/
    }
    else
    {
        printf("Managed to load the DLL!\n");
    }
}

// Exécuter le programme : Ctrl+F5 ou menu Déboguer > Exécuter sans débogage
// Déboguer le programme : F5 ou menu Déboguer > Démarrer le débogage

// Astuces pour bien démarrer : 
//   1. Utilisez la fenêtre Explorateur de solutions pour ajouter des fichiers et les gérer.
//   2. Utilisez la fenêtre Team Explorer pour vous connecter au contrôle de code source.
//   3. Utilisez la fenêtre Sortie pour voir la sortie de la génération et d'autres messages.
//   4. Utilisez la fenêtre Liste d'erreurs pour voir les erreurs.
//   5. Accédez à Projet > Ajouter un nouvel élément pour créer des fichiers de code, ou à Projet > Ajouter un élément existant pour ajouter des fichiers de code existants au projet.
//   6. Pour rouvrir ce projet plus tard, accédez à Fichier > Ouvrir > Projet et sélectionnez le fichier .sln.
