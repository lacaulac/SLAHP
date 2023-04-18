// SignatureTool.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include <iostream>
#include "SignUtils.h"
#include "base64.h"

void printUsage(char** argv);
void signFile(int argc, char** argv);
void genKeys(int argc, char** argv);
void verifySig(int argc, char** argv);
void hashFile(int argc, char** argv);

int main(int argc, char** argv)
{
    if (argc == 1)
    {
        printUsage(argv);
        return 2;
    }
    if (strcmp(argv[1], "sign") == 0)
        signFile(argc, argv);
    else if (strcmp(argv[1], "genkeys") == 0)
        genKeys(argc, argv);
    else if (strcmp(argv[1], "verify") == 0)
        verifySig(argc, argv);
    else if (strcmp(argv[1], "hash") == 0)
        hashFile(argc, argv);
    else
        printUsage(argv);
}

void printUsage(char** argv)
{
    printf("Usage:\n");
    printf("\t%s sign <file> <privateKey>\n", argv[0]);
    printf("\t%s genkeys <keypairName>\n", argv[0]);
    printf("\t%s verify <file> <publicKey>\n", argv[0]);
    printf("\t%s hash <file>\n", argv[0]);
}

void signFile(int argc, char** argv)
{
    printf("Signing!\n");
    char privKeyBuffer[2048] = { '\0' };
    char fileName[MAX_PATH] = { '\0' };
    FILE* tmpFile = NULL;

    fopen_s(&tmpFile, argv[3], "rb");
    fseek(tmpFile, 0, SEEK_END);
    long keySize = ftell(tmpFile);
    fseek(tmpFile, 0, SEEK_SET);
    fread(privKeyBuffer, keySize, 1, tmpFile);
    fclose(tmpFile);

    std::string privKeyB64(privKeyBuffer);
    auto cryptoProvider = getCryptoProvider();
    auto privKey = getPrivkeyBlobFromB64(cryptoProvider, privKeyB64);

    fopen_s(&tmpFile, argv[2], "rb");
    fseek(tmpFile, 0, SEEK_END);
    long fileContentSize = ftell(tmpFile);
    fseek(tmpFile, 0, SEEK_SET);
    BYTE* fileContent = (BYTE*)malloc(fileContentSize + 1);
    fread(fileContent, fileContentSize, 1, tmpFile);
    fclose(tmpFile);
    fileContent[fileContentSize] = '\0';

    if (fileContent[fileContentSize - 2] != '\r')
    {
        printf("ERROR\nERROR: Config files must be saved with CRLF format (\\r\\n line endings)\nERROR\n");
        ExitProcess(1);
    }

    std::string signedHash = signData(fileContent, fileContentSize, privKey, cryptoProvider);

    sprintf_s(fileName, MAX_PATH, "%s.sig", argv[2]);
    fopen_s(&tmpFile, fileName, "wb");
    fwrite(signedHash.c_str(), 1, strlen(signedHash.c_str()), tmpFile);
    fclose(tmpFile);
    free(fileContent);


    BCryptDestroyKey(privKey);
    BCryptCloseAlgorithmProvider(cryptoProvider, 0);
}

void genKeys(int argc, char** argv)
{
    printf("Generating keys...\n");
    auto cryptoProvider = getCryptoProvider();
    auto privKey = generateKeys(cryptoProvider);
    std::string privKeyb64 = getB64Privkey(privKey);
    std::string pubKeyb64 = getB64Pubkey(privKey);
    printf("Keys generated!");

    char fileName[MAX_PATH] = {'\0'};
    FILE* tmpFile = NULL;

    printf("Writing keys to %s.pub and %s.key...\n", argv[2], argv[2]);

    sprintf_s(fileName, MAX_PATH, "%s.pub", argv[2]);
    fopen_s(&tmpFile, fileName, "wb");
    fwrite(pubKeyb64.c_str(), 1, strlen(pubKeyb64.c_str()), tmpFile);
    fclose(tmpFile);
    printf("Wrote the public key inside %s.pub\n", argv[2]);

    sprintf_s(fileName, MAX_PATH, "%s.key", argv[2]);
    fopen_s(&tmpFile, fileName, "wb");
    fwrite(privKeyb64.c_str(), 1, strlen(privKeyb64.c_str()), tmpFile);
    fclose(tmpFile);
    printf("Wrote the private key inside %s.key\n", argv[2]);

    BCryptDestroyKey(privKey);
    BCryptCloseAlgorithmProvider(cryptoProvider, 0);
}

void verifySig(int argc, char** argv)
{
    printf("Verifying!\n");
    char pubKeyBuffer[2048] = { '\0' };
    BYTE* targetFile = NULL;
    char* targetHashBuffer = NULL;
    char fileName[MAX_PATH] = { '\0' };
    FILE* tmpFile = NULL;

    const char* nameTargetFile = argv[2];
    const char* namePubKeyFile = argv[3];

    fopen_s(&tmpFile, namePubKeyFile, "rb");
    fseek(tmpFile, 0, SEEK_END);
    long keySize = ftell(tmpFile);
    fseek(tmpFile, 0, SEEK_SET);
    fread(pubKeyBuffer, keySize, 1, tmpFile);
    fclose(tmpFile);
    std::string pubKeyB64(pubKeyBuffer);
    auto cryptoProvider = getCryptoProvider();
    auto pubKey = getPubkeyBlobFromB64(cryptoProvider, pubKeyB64);

    fopen_s(&tmpFile, nameTargetFile, "rb");
    fseek(tmpFile, 0, SEEK_END);
    long fileContentSize = ftell(tmpFile);
    fseek(tmpFile, 0, SEEK_SET);
    targetFile = (BYTE*)malloc(fileContentSize + 1);
    fread(targetFile, fileContentSize, 1, tmpFile);
    fclose(tmpFile);
    targetFile[fileContentSize] = '\0';

    sprintf_s(fileName, MAX_PATH, "%s.sig", nameTargetFile);
    fopen_s(&tmpFile, fileName, "rb");
    fseek(tmpFile, 0, SEEK_END);
    long hashFileContentSize = ftell(tmpFile);
    fseek(tmpFile, 0, SEEK_SET);
    targetHashBuffer = (char*)malloc(hashFileContentSize + 1);
    fread(targetHashBuffer, hashFileContentSize, 1, tmpFile);
    fseek(tmpFile, 0, 0);
    fclose(tmpFile);

    std::string hashStr(targetHashBuffer);
    bool isValid = checkSignature(targetFile, fileContentSize, hashStr, pubKey, cryptoProvider);

    printf("%s's signature is %s.\n", nameTargetFile, isValid ? "valid" : "invalid");

    free(targetFile);
    free(targetHashBuffer);
}

void hashFile(int argc, char** argv)
{
    printf("Hashing!\n");
    BYTE* targetFile = NULL;
    FILE* tmpFile = NULL;

    const char* nameTargetFile = argv[2];

    fopen_s(&tmpFile, nameTargetFile, "rb");
    fseek(tmpFile, 0, SEEK_END);
    long fileContentSize = ftell(tmpFile);
    fseek(tmpFile, 0, SEEK_SET);
    targetFile = (BYTE*)malloc(fileContentSize);
    fread(targetFile, fileContentSize, 1, tmpFile);
    fclose(tmpFile);
    targetFile[fileContentSize] = '\0';
    size_t stringLength = strlen((char*)targetFile);

    printf("%s's hash is %s.\n", nameTargetFile, hashToB64(targetFile, stringLength).c_str());


    free(targetFile);
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
