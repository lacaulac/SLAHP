// PerfTests.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include <iostream>
#include "../Protector/framework.h"
#include <chrono>

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("Usage: %s nothing/protector/protectorsigned/policyget/ldlib/ldlibprot/ldlibproturl <dllName(ldlibs) / cache(policies)[No/yes]> <cfgUrl>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "nothing") == 0)
    {
        auto start_time = std::chrono::high_resolution_clock::now();
        auto stop_time = std::chrono::high_resolution_clock::now();
        auto time = stop_time - start_time;
        std::cout << time / std::chrono::nanoseconds(1) << "ns" << std::endl;
        return 0;
    }
    else if (strcmp(argv[1], "protector") == 0)
    {
        bool useCache = false;
        if (argc > 2)
        {
            if (strcmp(argv[2], "yes") == 0)
            {
                useCache = true;
            }
        }

        auto start_time = std::chrono::high_resolution_clock::now();
        InitProtector(L"HijackProtector", L"lacaulac.ovh", L"/stage3a/perftests.cfg", true, true, NULL, useCache, false);
        auto stop_time = std::chrono::high_resolution_clock::now();
        auto time = stop_time - start_time;
        std::cout << time / std::chrono::nanoseconds(1) << "ns" << std::endl;
        return 0;
    }
    else if (strcmp(argv[1], "protectorsigned") == 0)
    {
        bool useCache = false;
        if (argc > 2)
        {
            if (strcmp(argv[2], "yes") == 0)
            {
                useCache = true;
            }
        }
        auto start_time = std::chrono::high_resolution_clock::now();
        InitProtector(L"HijackProtector", L"lacaulac.ovh", L"/stage3a/perftests.cfg", true, true, "UlNBMQAIAAADAAAAAAEAAAAAAAAAAAAAAQABv65V7AiIxjmiz4l2xv3srLSF/ZZMv6M9nEWRIu0iRit4+rCNrsIONr/p94dwteHsUHUR6IZ+sh931uDGjl3tO35zw5oI6TfQcVOi020sa56yY2N2PgC/zuTgsgmKKC2+P783MvhRjVriCMzF7+MRhSUZWODJF+VXbZavAT2jffnPR3sP3yVGb13k6Jji04N5Ix1RJzVjl3+0E1w9Vs+tpq3RNlywfQqA0XOVMryPIFhffT2Zt3hgTBfSaPXcgdy+MCoJJ67PjR+LrbTHAAvKZcawTnT0Gl/OKlMTmhWLv+MoQIPj4qn0F6D3+xIJb2kjg4yx4QJslqgeULITBbw3QQ==", useCache, false);
        auto stop_time = std::chrono::high_resolution_clock::now();
        auto time = stop_time - start_time;
        std::cout << time / std::chrono::nanoseconds(1) << "ns" << std::endl;
        return 0;
    }
    else if (strcmp(argv[1], "policyget") == 0)
    {
        auto start_time = std::chrono::high_resolution_clock::now();
        std::string cfgFile = GetRequest(L"HijackProtector", L"lacaulac.ovh", L"/stage3a/perftests.cfg", true, true, "ENDCONFIG\r\n");
        auto stop_time = std::chrono::high_resolution_clock::now();
        auto time = stop_time - start_time;
        std::cout << time / std::chrono::nanoseconds(1) << "ns" << std::endl;
        return 0;
    }
    if (argc < 3)
    {
        printf("You need to provide the dll name / path as a third parameter");
        DebugBreak();
        return 1;
    }
    if (strcmp(argv[1], "ldlib") == 0)
    {
        auto start_time = std::chrono::high_resolution_clock::now();
        LoadLibraryA(argv[2]);
        auto stop_time = std::chrono::high_resolution_clock::now();
        //MessageBoxA(NULL, "", "", MB_OK);
        auto time = stop_time - start_time;
        std::cout << time / std::chrono::nanoseconds(1) << "ns" << std::endl;
        return 0;
    }
    else if (strcmp(argv[1], "ldlibprot") == 0)
    {
		InitProtector(L"HijackProtector", L"lacaulac.ovh", L"/stage3a/perftests.cfg", true, true, NULL, false, false, true);
        auto start_time = std::chrono::high_resolution_clock::now();
        LoadLibraryA(argv[2]);
        auto stop_time = std::chrono::high_resolution_clock::now();
        //MessageBoxA(NULL, "", "", MB_OK);
        auto time = stop_time - start_time;
        std::cout << time / std::chrono::nanoseconds(1) << "ns" << std::endl;
        return 0;
    }

    else if (strcmp(argv[1], "ldlibproturl") == 0)
    {
        char* cfgUrl = argv[3];
        size_t buffSize = (strlen(cfgUrl) + 1) * 2;
        LPWSTR cfgUrlW = (LPWSTR)calloc(1, buffSize);
        MultiByteToWideChar(CP_ACP, 0, cfgUrl, -1, cfgUrlW, buffSize);
        InitProtector(L"HijackProtector", L"lacaulac.ovh", cfgUrlW, true, true, NULL, false, false, true);
        auto start_time = std::chrono::high_resolution_clock::now();
        LoadLibraryA(argv[2]);
        auto stop_time = std::chrono::high_resolution_clock::now();
        //MessageBoxA(NULL, "", "", MB_OK);
        auto time = stop_time - start_time;
        std::cout << time / std::chrono::nanoseconds(1) << "ns" << std::endl;
        free(cfgUrlW);
        return 0;
    }
    else
    {
        printf("Unknown test: \"%s\".\n", argv[1]);
        return 1;
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
