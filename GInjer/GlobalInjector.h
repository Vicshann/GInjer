
#pragma once
/*
  Copyright (c) 2019 Victor Sheinmann, Vicshann@gmail.com

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
  to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
*/

//#define TESTRUN          // Skip driver loading

#define PROTSLFMSK 0     // PROCESS_CREATE_THREAD  PROCESS_VM_OPERATION  PROCESS_VM_READ  PROCESS_VM_WRITE  PROCESS_DUP_HANDLE 
#define PROTTGTMSK 0
#define SERVICE_NAME ""  // Unused
#define CFGSECNAME L"Parameters"
#define NAMSECNAME L"NameMarkers"

#define WIN32_LEAN_AND_MEAN    
#define ctNoProtStack    // Reduces size of injected loader     

#include "Common.hpp"
//#include <windows.h>
//#include "Utils.h"
#include "DrvLoader.hpp"
#include "CBProcess.hpp"
#include "wow64ext.hpp"
//#include "FormatPE.h"
//#include "CompileTime.hpp"
#include "LoaderCode.h"
//#include "HDE.h"
//#include "UniHook.hpp"
//#include "InjDllLdr.hpp"
#include "SrvControl.hpp"
#include "Paq8.hpp"

//------------------------------------------------------------------------------------------------------------
static const int NameExtSize    = 16;    // 15 chars + null
static const int LdrDirNamesCnt = 2;
static const int ModuleNamesCnt = 4;     // 4 file open tries per directory

typedef CGrowArray<wchar_t> CWStrBuf;
//------------------------------------------------------------------------------------------------------------
struct SNtDllDesc
{
 BOOL IsX32LdrInitStdcall;
 UINT64 AddrOfLdrSystemDllInitBlock;
 UINT64 NtDllBase32;
 UINT64 NtDllBase64;
 UINT NtDllSize32;
 UINT NtDllSize64;
 UINT OffsLdrpInitRet32;     
 UINT OffsLdrpInitRet64;
 UINT OffsLdrpInitialize32;     
 UINT OffsLdrpInitialize64;
 UINT OffsLdrpInitPatch32;
 UINT OffsLdrpInitPatch64;
 UINT OffsLdrInitializeThunk32;
 UINT OffsLdrInitializeThunk64;
 BYTE OrigLdrInitializeThunk32[32];
 BYTE OrigLdrInitializeThunk64[32];
 BYTE CodeNtMapViewOfSection[64];
 BYTE CodeNtUnmapViewOfSection[64];
 BYTE LdrSystemDllInitBlock[256];      // Starts with 'DWORD Size' 
};
//------------------------------------------------------------------------------------------------------------
struct SPathHandleDescr
{
 DWORD Flags;
 HANDLE hFSObj;
 CWStrBuf Path;    // No terminating 0

 int SetDosPathByHandle(PWSTR OptPath, UINT OptPathLen)    // GetModuleFileNameW for a injected DLL will return the same path which was used to load it. And not everybody can handle '\??\HarddiskVolumeX\' there ;) 
  {
   if(OptPath)                // Should result in a shorter path than '\??\HarddiskVolumeX\'
    {
     if(!OptPathLen)OptPathLen = lstrlenW(OptPath);   // not including the terminating null character
     Path.Resize(OptPathLen);
    }
     else Path.Resize(MAX_PATH);
   DWORD Len = GetFinalPathNameByHandleW(this->hFSObj, this->Path.c_data(), this->Path.Count()+1, VOLUME_NAME_DOS);   // Path size must include the terminating null character
   if(!Len && (GetLastError() == ERROR_FILE_NOT_FOUND)){LOGMSG("Hidden volumes are not supported! Try DISKPART -> attributes volume clear hidden"); return 0;}              
   if(!Len){LOGMSG("GetFinalPathNameByHandleW failed with %u!", GetLastError()); return 0;}    
   if(Len > this->Path.Count()) // Resize the buffer and try again  // Len does not include 0 if W version is used
    {
     Path.Resize(Len-1);
     Len = GetFinalPathNameByHandleW(this->hFSObj, this->Path.c_data(), this->Path.Count()+1, VOLUME_NAME_DOS); 
    }
   int  offs = 0;
   PWSTR Ptr = this->Path.c_data();
   while(Ptr[offs] && (Ptr[offs] != ':'))offs++;  // And '\\?\C:\' is not acceptable either
   if(offs > 0)
    {
     offs--;
     Len -= offs;
     memcpy(Ptr, &Ptr[offs], Len*sizeof(WCHAR));
    }
   Path.Resize(Len);
   this->Path.c_data()[Len] = 0;
   DBGMSG("Normalized Path: %ls",this->Path.c_data());
   return this->Path.Count();
  }
};

class CModPathArr
{
 CGrowArray<SPathHandleDescr> Array;

public:
 SPathHandleDescr* Get(UINT Idx){return &this->Array.c_data()[Idx];}
 SPathHandleDescr* Add(SPathHandleDescr* Obj){return this->Array.Append(Obj, 1);}
 UINT Count(void){return this->Array.Count();}
 CModPathArr(void){memset(this,0,sizeof(CModPathArr));}
 ~CModPathArr()
 {
  for(UINT ctr=0;ctr < this->Array.Count();ctr++)
   {
    SPathHandleDescr* Obj = &this->Array.c_data()[ctr];
    if(Obj->hFSObj)CloseHandle(Obj->hFSObj);
   }
 }
};
//------------------------------------------------------------------------------------------------------------
struct SNameExtCfg
{
 DWORD Flags;
 wchar_t* Name;
 int ValLen;        // Set by INI load function
 wchar_t Value[NameExtSize];
};
//------------------------------------------------------------------------------------------------------------
struct SInjProcDesc
{
 HANDLE hProcess;       // Opened in callback
 HANDLE hMainThread;    // Left in suspended state (The only useful thing that can be done with from driver callback)
 int    InjType;
 CWStrBuf ProcPath;

// LdrLoadLdd accepts only '\\?\HarddiskVolume6\TEST\GINJER\TestProcess32.exe.ad'
// NtOpenFile accepts only '\??\HarddiskVolume6\TEST\GINJER\TestProcess32.exe.ad'
//
void Assign(HANDLE hPr, HANDLE hTh, PWSTR Path, UINT PathLen=0)      // Path format: '\Device\HarddiskVolume1\'
{
 DBGMSG("Push: hPr=%08X, hTh=%08X, PLen=%u, Path=%ls",hPr,hTh,PathLen,Path);
 this->hProcess    = hPr;
 this->hMainThread = hTh;
 if(Path)
  {
   if(!PathLen)PathLen = lstrlenW(Path);
   if(NSTR::IsStrEqualIC(Path, L"\\Device\\", 8))  
    {
     PathLen  -= 4;
     this->ProcPath.Assign(NULL, PathLen);
     PWSTR Ptr = this->ProcPath.c_data();     
     lstrcpynW(Ptr, &Path[4], PathLen+1);
     *Ptr = '\\';
     Ptr[1] = Ptr[2] = '?';     
    }  
     else 
      {
       this->ProcPath.Assign(Path, PathLen);
       this->ProcPath.c_data()[PathLen] = 0;
       if(this->ProcPath.c_data()[1] == '\\')this->ProcPath.c_data()[1] = '?';
      }
  }
}

void Close(void)
 {
  this->ProcPath.Resize(0);   
  if(this->hMainThread)CloseHandle(this->hMainThread);
  if(this->hProcess)CloseHandle(this->hProcess);
 }

};
//------------------------------------------------------------------------------------------------------------

bool _stdcall DoAppFinalization(void);
bool _stdcall DoAppInitialization(void); 
void _stdcall LoadConfiguration(void);    
int  _stdcall InitNtDllsHooks(void);   
int _fastcall GenerateBinDrv(void);   
int _fastcall SaveDriverToFile(PWSTR Name, bool IsX64, PWSTR FilePathOut, PWSTR NormPathOut, bool Alt);    
//------------------------------------------------------------------------------------------------------------
