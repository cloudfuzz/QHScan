# QHScan

This is a custom scanner client for **Quick Heal Anti-Malware Scanner Engine**. This can be directly used for fuzzing with **WinAFL**.


## Tested bed

* Windows 7 SP1 x86
* Quick Heal 18.00 (11.1.1.26) x86


# Usage

```bat
QHScan.exe C:\malware.exe
```


## Fuzzing

```bat
..\winafl-cmin.py -v -D C:\DynamoRIO\bin32 -t 100000 -i C:\av -o C:\minset -covtype edge -coverage_module SCANSDK.DLL -coverage_module platform.qvd -coverage_module filesdk.qvd -coverage_module ggstub.dll -coverage_module onlnmf.dll -coverage_module diskapi.dll -coverage_module bdsitf.dll -coverage_module infori.dll -coverage_module FileWrap.dll -coverage_module registry.dll -coverage_module opsitf.dll -coverage_module catitf.dll -coverage_module disasm.qvd -coverage_module dataproc.qvd -coverage_module qhpicln.dll -coverage_module engncore.qvd -coverage_module pescan.qvd -coverage_module pepoly.qvd -coverage_module arcvsdk.qvd -coverage_module lzesdk.qvd -coverage_module heurscan.qvd -coverage_module npesdk.qvd -coverage_module boot.qvd -coverage_module miscscan.qvd -coverage_module webcat.dll -coverage_module qhkill.qvd -target_module qhscan.exe -target_method ScanFile -nargs 1 -w 4 -- C:\QHScan.exe @@

afl-fuzz.exe -M master0 -i C:\minset -o C:\fuzz -D C:\DynamoRIO\bin32 -t 20000 -- -covtype edge -coverage_module SCANSDK.DLL -coverage_module platform.qvd -coverage_module filesdk.qvd -coverage_module ggstub.dll -coverage_module onlnmf.dll -coverage_module diskapi.dll -coverage_module bdsitf.dll -coverage_module infori.dll -coverage_module FileWrap.dll -coverage_module registry.dll -coverage_module opsitf.dll -coverage_module catitf.dll -coverage_module disasm.qvd -coverage_module dataproc.qvd -coverage_module qhpicln.dll -coverage_module engncore.qvd -coverage_module pescan.qvd -coverage_module pepoly.qvd -coverage_module arcvsdk.qvd -coverage_module lzesdk.qvd -coverage_module heurscan.qvd -coverage_module npesdk.qvd -coverage_module boot.qvd -coverage_module miscscan.qvd -coverage_module webcat.dll -coverage_module qhkill.qvd -target_module qhscan.exe -target_method ScanFile -nargs 1 -- C:\QHScan.exe @@
afl-fuzz.exe -S slave0 -i C:\minset -o C:\fuzz -D C:\DynamoRIO\bin32 -t 20000 -- -covtype edge -coverage_module SCANSDK.DLL -coverage_module platform.qvd -coverage_module filesdk.qvd -coverage_module ggstub.dll -coverage_module onlnmf.dll -coverage_module diskapi.dll -coverage_module bdsitf.dll -coverage_module infori.dll -coverage_module FileWrap.dll -coverage_module registry.dll -coverage_module opsitf.dll -coverage_module catitf.dll -coverage_module disasm.qvd -coverage_module dataproc.qvd -coverage_module qhpicln.dll -coverage_module engncore.qvd -coverage_module pescan.qvd -coverage_module pepoly.qvd -coverage_module arcvsdk.qvd -coverage_module lzesdk.qvd -coverage_module heurscan.qvd -coverage_module npesdk.qvd -coverage_module boot.qvd -coverage_module miscscan.qvd -coverage_module webcat.dll -coverage_module qhkill.qvd -target_module qhscan.exe -target_method ScanFile -nargs 1 -- C:\QHScan.exe @@
```


## Author

> **Ashfaq Ansari**  
ashfaq[at]cloudfuzz[dot]io  
**[@HackSysTeam](https://twitter.com/HackSysTeam) | [Blog](http://hacksys.vfreaks.com/ "HackSys Team")**  
