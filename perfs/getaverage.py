import sys
import os

def getAverageForFile(fileName):
    with open("logs/" + fileName, "r", encoding="utf-16") as fl:
        ctn = fl.read()
        total = int(0)
        lines = ctn.split("\n")
        lineAmount = 0
        for line in lines:
            if line.endswith("ns"):
                val = line.split("ns")[0]
                if val == "":
                    continue
                lineAmount += 1
                total += int(val)
        # print("Total : %d. Lines amount: %d. Average : %f" % (total, lineAmount, (total/lineAmount)/1000.0))
        return ((total/lineAmount)/1000.0)

if len(sys.argv) == 2:
    print("%s :\t\tAverage time:\t%09fµs" % (sys.argv[1], getAverageForFile(sys.argv[1])))
else:
    logFiles = os.listdir("logs")
    for fileName in logFiles:
        avg = round(getAverageForFile(fileName))
        avg = str(avg) + (" "*(8 - len(str(avg))))
        print("%sµs\t\t%s" % (avg, fileName))