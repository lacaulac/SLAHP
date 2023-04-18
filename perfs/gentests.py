from distutils.command.config import config
import requests
import os

libList = ["lib_0_deps_main.dll", "lib_6_deps_main.dll", "lib_12_deps_main.dll"]
testList = {
    "AllowHash": {
        "directory": "dll_unsigned",
        "config": "perfv2/allowhash.cfg"
    },
    "DisallowHash": {
        "directory": "dll_unsigned",
        "config": "perfv2/disallowhash.cfg"
    },
    "AllowSigned": {
        "directory": "dll_signed",
        "config": "perfv2/sig.cfg"
    },
    "DisallowSigned": {
        "directory": "dll_signed_invalid",
        "config": "perfv2/sig.cfg"
    }
}

def checkExists(path):
    if not os.path.exists(path):
        print(f"Path {path} does not exist.")
        exit()

def putInForLoop(code, repetitionAmount):
    return f"for ($num = 1 ; $num -le {repetitionAmount} ; $num++) {{ {code} }}\n"

def getTestLine_internal(libPath, cfgPath, caseName, repetitionAmount, isProtected=True):
    checkExists(libPath)
    libnameStripped = libPath.split("/")[-1].split(".dll")[0]
    cfgName = cfgPath.split("/")[-1].split(".cfg")[0]
    if not isProtected:
        return f'echo "Witness for {libnameStripped} "; for ($num = 1 ; $num -le {repetitionAmount} ; $num++){{.\PerfTests.exe ldlib {libPath} >> logs/{libnameStripped}-witness.log }}\n'
    return f'echo "{libPath} + {cfgName} = {caseName}"; for ($num = 1 ; $num -le {repetitionAmount} ; $num++){{.\PerfTests.exe ldlibproturl {libPath} /stage3a/{cfgPath} >> logs/{libnameStripped}-{cfgName}-{caseName}.log }}\n'

def getLinesForDllPath(libName, repetitions):
    lines = []
    lines.append(getTestLine_internal("./" + testList["AllowHash"]["directory"] + "/" + libName, "", "", repetitions, False)) #Get witness line
    for caseName, caseData in testList.items(): #For each test case
        libPath = "./" + caseData["directory"] + "/" + libName #Get lib path
        lines.append(getTestLine_internal(libPath, caseData["config"], caseName, repetitions)) #Get test line
    return lines

def getWitnessTestLine(libname):
    libnameStripped = libname.split(".dll")[0]
    return f'echo "{libname}[Witness]"; for ($num = 1 ; $num -le {repetitionAmount} ; $num++){{.\PerfTests.exe ldlib .\DLLs\Signed\{libname} >> logs/{libnameStripped}-witness.log }}\n'

dirCaseCorrespondance = {
    "Blocked": "HashInvalid",
    "AllowUnspec": "HashInvalid",
    "AllowSigned": "Signed",
    "AllowHash": "HashValid",
    "Witness": "Signed"
}

repetitionAmount = 500

def writeProtectorInitTests(fl):
    fl.write(".\PerfTests protectorsigned yes\n")
    fl.write(putInForLoop(".\PerfTests.exe protectorsigned yes >> logs/initprotector_cached_signed.log", repetitionAmount))
    fl.write(putInForLoop(".\PerfTests.exe protector yes >> logs/initprotector_cached_unsigned.log", repetitionAmount))
    fl.write("rm policy*\n")

with open("runtests.ps1", "w") as fl:
    writeProtectorInitTests(fl)
    for libName in libList:
        for line in getLinesForDllPath(libName, repetitionAmount):
            fl.write(line)
    # for libName in libs:
    #     writeTestsForOneLib(libName, fl)

print("Testing config availability...")

for caseName, caseData in testList.items(): #For each test case
    cfgName = caseData["config"].split("/")[-1].split(".cfg")[0]
    url = f'https://lacaulac.ovh/stage3a/' + caseData["config"]
    res = requests.get(url)
    if "ENDCONFIG" in str(res.content, encoding="utf-8"):
        print(f'\t${cfgName} ok.')
    else:
        print(f'\t${cfgName} invalid.')