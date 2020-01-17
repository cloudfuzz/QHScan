/*++

     #######  ##     ##  ######   ######     ###    ##    ##
    ##     ## ##     ## ##    ## ##    ##   ## ##   ###   ##
    ##     ## ##     ## ##       ##        ##   ##  ####  ##
    ##     ## #########  ######  ##       ##     ## ## ## ##
    ##  ## ## ##     ##       ## ##       ######### ##  ####
    ##    ##  ##     ## ##    ## ##    ## ##     ## ##   ###
     ##### ## ##     ##  ######   ######  ##     ## ##    ##

                 Quick Heal Scanner Client

Author : Ashfaq Ansari
Contact: ashfaq[at]cloudfuzz[dot]io
Twitter: @HackSysTeam
Website: http://www.cloudfuzz.io/

Copyright (C) 2019-2020 CloudFuzz Technolabs Pvt. Ltd. All rights reserved.

This program is free software: you can redistribute it and/or modify it under the terms of
the GNU General Public License as published by the Free Software Foundation, either version
3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.
If not, see <http://www.gnu.org/licenses/>.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

See the file 'LICENSE' for complete copying permission.

--*/

#pragma once

#ifndef __QH_SCAN_H__
#define __QH_SCAN_H__

#include <stdio.h>
#include <Windows.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma warning(disable:4996)
#pragma warning(disable:4309)


/**
 * Do not build in x64 mode as we do not have the right offsets for them
 */

#ifdef _WIN64
#error "x64 mode not supported"
#endif


/**
 * Defines
 */

#define BANNER \
("                                                                       \n" \
 "         #######  ##     ##  ######   ######     ###    ##    ##       \n" \
 "        ##     ## ##     ## ##    ## ##    ##   ## ##   ###   ##       \n" \
 "        ##     ## ##     ## ##       ##        ##   ##  ####  ##       \n" \
 "        ##     ## #########  ######  ##       ##     ## ## ## ##       \n" \
 "        ##  ## ## ##     ##       ## ##       ######### ##  ####       \n" \
 "        ##    ##  ##     ## ##    ## ##    ## ##     ## ##   ###       \n" \
 "         ##### ## ##     ##  ######   ######  ##     ## ##    ##       \n" \
 "                                                                       \n" \
 "                         Quick Heal Scanner Client                     \n" \
 "                                                                       \n")

#define DEBUG(Format, ...)  printf(Format, __VA_ARGS__)


/**
 * Structures
 */

typedef enum _QH_SCAN_CODES
{
    QH_SCAN_INFECTED1 = 0x3E9,
    QH_SCAN_UNKNOWN = 0x3EA,
    QH_SCAN_ARCHIVE = 0x3EB,
    QH_SCAN_INFECTED_ARCHIVE = 0x3EC,
    QH_SCAN_IO_ERROR = 0x3ED,
    QH_SCAN_INFECTED2 = 0x3EF,
    QH_SCAN_CONTINUE = 0x7D5,
    QH_SCAN_REPAIRED = 0xBB9,
    QH_SCAN_SKIPPED = 0xBBA,
    QH_SCAN_DELETED = 0xBBB,
    QH_SCAN_UNREPAIRABLE = 0xBBC,
    QH_SCAN_MARKED_FOR_DELETION = 0xBBE
} QH_SCAN_CODES;

typedef struct _INITSCAN_1 {
    SHORT Size;                 // sizeof(INITSCAN_1) // 0x021e
    SHORT field_2;              // 0x1
    SHORT field_4;              // 0x2
    SHORT field_6;              // 0x1
    SHORT field_8;              // 0x1
    CHAR QuickHealDir[0x100];
    CHAR TempDir[0x100];
    SHORT field_210;            // 0x0
    SHORT field_212;            // 0x017f
    SHORT field_214;            // 0x540a
    SHORT field_216;            // 0xfc6e
    SHORT field_218;            // 0x0
    SHORT field_220;            // 0x0
    SHORT field_222;            // 0x0
    SHORT field_224;            // 0x0
    SHORT field_226;            // 0x0
    SHORT field_228;            // 0x0
} INITSCAN_1, *PINITSCAN_1;

typedef struct _INITSCAN_2 {
    ULONG_PTR field_0;          // 0x0 
    ULONG_PTR field_4;          // 0x11
    DWORD CurrentPid;           // PID of current process
    ULONG_PTR field_C;          // 0x4
    ULONG_PTR field_10;         // 0x0
    ULONG_PTR field_14;         // 0x0
} INITSCAN_2, *PINITSCAN_2;

typedef struct _CALLBACK_PARAM_1 {
    SHORT Code;
    CHAR FilePath[1030];
    CHAR DetectionDescription[50];
    SHORT SuspiciousIndicator;
    SHORT SuspiciousIndicatorCode;
} CALLBACK_PARAM_1, *PCALLBACK_PARAM_1;


/**
 * Function type definition
 */

typedef INT(WINAPI *QhInitScanForSAS_t)(
    _In_ PINITSCAN_1 Parma1,
    _In_ PINITSCAN_2 Param2,
    _Out_ PVOID OutBuffer
    );

typedef INT(WINAPI *QhSetCallbackForSAS_t)(
    _In_ INT a1,
    _In_ PVOID CallBack
    );

typedef INT(WINAPI *QhOpenFileForSAS_t)(
    _In_ INT a1,
    _In_ PCHAR FilePath,
    _In_ INT a3,
    _In_ INT a4,
    _Out_ PVOID OutBuffer
    );

typedef INT(WINAPI *QhGetFileTypeForSAS_t)(
    _In_ ULONG_PTR OutBufferQhOpenFileForSAS,
    _Out_ PVOID OutBuffer1,
    _Out_ PVOID OutBuffer2
    );

typedef INT(WINAPI *QhScanFileEx_t)(
    _In_ ULONG_PTR OutBufferQhOpenFileForSAS,
    _Out_ PVOID OutBuffer
    );

typedef INT(WINAPI *QhCloseFile_t)(
    _In_ PVOID OpenFileForSASOutBufferAddress
    );

typedef INT(WINAPI *QhDeinitScanForSAS_t)(
    _In_ INT a1
    );

QhInitScanForSAS_t QhInitScanForSAS = NULL;
QhSetCallbackForSAS_t QhSetCallbackForSAS = NULL;
QhOpenFileForSAS_t QhOpenFileForSAS = NULL;
QhGetFileTypeForSAS_t QhGetFileTypeForSAS = NULL;
QhScanFileEx_t QhScanFileEx = NULL;
QhCloseFile_t QhCloseFile = NULL;
QhDeinitScanForSAS_t QhDeinitScanForSAS = NULL;


/**
 * Function declarations
 */

VOID
InitializeQuickHealEngine(
    VOID
);

INT
WINAPI
ScanCallback(
    _In_ PCALLBACK_PARAM_1 CallbackParam,
    _In_ INT a2
);

VOID
ScanFilesInDrectory(
    _In_ PCHAR Directory
);

BOOL
__declspec(dllexport)
ScanFile(
    _In_ PCHAR PathToScan
);

/*
API call sequence (all of the APIs return value 1 when success)

scansdk!QhInitScanForSAS
scansdk!QhSetCallbackForSAS
scansdk!QhOpenFileForSAS
scansdk!QhGetFileTypeForSAS
scansdk!QhScanFileEx
scansdk!QhCloseFile
scansdk!QhDeinitScanForSAS
*/

#endif // !__QH_SCAN_H__
