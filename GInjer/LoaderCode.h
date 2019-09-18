
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


#include <Windows.h>

//===========================================================================================================
#define ModDescFromCurTh() ((NtCurrentTeb()->LastErrorValue > 0xFFFF)?((SModDesc*)NtCurrentTeb()->LastErrorValue):(NULL)) 
#define AddrToBlkDesc(addr) ((SBlkDesc*)(((SIZE_T)(addr)) & ~((SIZE_T)0xFFFF)))
#define GetCurLdrDesc(blkBase) ((blkBase)?((4 == sizeof(PVOID))?(&((SBlkDesc*)blkBase)->LdrDesc32):(&((SBlkDesc*)blkBase)->LdrDesc64)):(NULL))
#define LDR_STRUCT_ALIGN     16            // For InjLdr::RemThModMarker
#define DLL_REFLECTIVE_LOAD  15

#define LDRLOG(msg,...) MsgLogToLdr(__FUNCTION__,msg,__VA_ARGS__) 
//---------------------------------------------------------------------------
// mfReflLoad       // Let DLL itself execute loading (Memory allocated enough for its VirtualSize and its DllMain is called)
// mfLoaderLoad     // LdrLoadDll is called for an injected DLL
// mfLocalPath      // Load module only if it on same path as EXE
// mfGlobalPath     // Load module for any path backward from EXE
// mfModNative      // Load x64 modules only in x64 processes, not in WOW64
// mfModXAny        // x64 module can be loaded in WOW64 process when loading before system loader execution

enum EModFlags {         
// Stored in PE header (Major version)
       mfPresent    = 0x0001,      // Marks that the module is supported (should it always be set?)
       mfReflLoad   = 0x0002,      // else mfLoaderLoad
       mfLocalPath  = 0x0004,      // else mfGlobalPath
       mfModXAny    = 0x0008,      // else mfModNative
       mfBeforeInit = 0x0010,      // Load before process initialization (Reflective only) (Else will be loaded on first LdrLoadDll call)

// Module name flags
       mfBeforeLdr  = 0x0100,      // Before first LdrpInitialize (Before all static imported DLLs loaded)  // Process/Thread is not initialized yet at this point
       mfAfterLdr   = 0x0200,      // After first LdrpInitialize (After all static imported DLLs loaded)
       mfModuleX32  = 0x0400,      // Detected by PE header instead
       mfModuleX64  = 0x0800,      // Detected by PE header instead

// Working flags
       mfModOnRoot  = 0x1000,
       mfModLoaded  = 0x2000       // The module is already loaded
};
//---------------------------------------------------------------------------
#pragma pack(push,1)
struct SModDesc    // Aligned at 8 bytes in memory   // This one s passed to module`s DllMain (Reflective loading only)
{
 DWORD   PrevSize;        // SInjModDesc + Path + Alignment  // 0 for a first entry
 DWORD   NextOffs;        // SInjModDesc + Path + Alignment  // 0 for a last entry
 DWORD   Flags;
 DWORD   PathSize;        // In chars, not including 0
 DWORD   ModSize;         // Full virtual size  // For reflective injection, NULL otherwise
 DWORD   ModEPOffs;       // For reflective injection, NULL otherwise
 DWORD   ModRawSize;      // For reflective injection, NULL otherwise
 UINT64  ModuleBase;      // For reflective injection, NULL otherwise
 wchar_t ModulePath[1];   // 0-terminated
};
//---------------------------------------------------------------------------
enum ELDescFlg { dfNotEmpty=1, dfThisIsWow64=2, dfStdcallLdrpInit=4};

struct SLdrDesc    // Stored at remote memory BlockBase  
{
 UINT64  NtDllBase;
 UINT64  PNtDllProcs;   // Pointer (Local, on stack of the loader)
 UINT64  LdrProcAddr;
 UINT64  AddrOfLdrpInit;
 UINT64  LdrpInitRetAddr;     // Original return address from LdrpInitialize 
 UINT64  AddrOfLdrInitThunk;
 ULONG   OldProtLdrInitThunk;
 DWORD   Flags; 
 BYTE    OrigLdrInitThunk[32];   
};
//---------------------------------------------------------------------------
struct SNtDllProcs     // x32 or x64
{
 NTSTATUS (NTAPI* pNtClose)(HANDLE Handle);
 NTSTATUS (NTAPI* pLdrLoadDll)(PCWSTR,PULONG,PUNICODE_STRING,PVOID*);
 NTSTATUS (NTAPI* pNtUnmapViewOfSection)(HANDLE,PVOID);
 NTSTATUS (NTAPI* pNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
 NTSTATUS (NTAPI* pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
 NTSTATUS (NTAPI* pNtOpenSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
 NTSTATUS (NTAPI* pNtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
//--- Additional 
 NTSTATUS (NTAPI* pNtWriteFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
 int (__cdecl* pVSprintf)(char *Dest, const char *Format, va_list Args);
};
//---------------------------------------------------------------------------
struct SBlkDesc
{
 SLdrDesc LdrDesc32;   
 SLdrDesc LdrDesc64;  
 UINT64   hDbgLogOutA;      // Use it only for injection debugging!   // One is some console handle and another is a file or a pipe handle
 UINT64   hDbgLogOutB;      // Use it only for injection debugging!
 UINT64   AddrOfLdrSystemDllInitBlock;
 UINT64   AddrOfContext;
 DWORD    ModDescLstOffs;   // From BlockBaseAddr base. Offset of first SModDesc 
 BYTE     CodeNtMapViewOfSection[64];
 BYTE     CodeNtUnmapViewOfSection[64];
 BYTE     LdrSystemDllInitBlock[256];      // Starts with 'DWORD Size' // Initialized by PspPrepareSystemDllInitBlock   // 128 bytes, for now     // NOTE: Random will be same as of loader process
};

#pragma pack(pop)
//---------------------------------------------------------------------------
static void   _cdecl MsgLogToLdr(char* ProcName, char* MsgFmt, ...)
{
 static HANDLE hLogOutA; 
 static HANDLE hLogOutB;
 static int (__cdecl* pVSprintf)(char *Dest, const char *Format, va_list Args);
 static NTSTATUS (NTAPI* pNtWriteFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

 struct ST     // To avoid import of 'sprintf'
  {  
   static int _cdecl Format(void* pVSprintf, char* OutBuf, ...)  
    {
     va_list args;
     va_start(args,OutBuf);
     int res = ((int (__cdecl*)(char *, const char *, va_list))pVSprintf)(OutBuf,"%08X%08X %06X:%06X %s -> ",args);
     va_end(args);
     return res;
    }
  };
 va_list args;
 if(!MsgFmt)
  {
   if(!ProcName)return;
   SModDesc* ModDesc = (SModDesc*)ProcName;
   SBlkDesc* BlkDesc = AddrToBlkDesc(ModDesc);
   SLdrDesc* LdrDesc = GetCurLdrDesc(BlkDesc); 
   if(!LdrDesc->NtDllBase || (!BlkDesc->hDbgLogOutA && !BlkDesc->hDbgLogOutB))return;
   hLogOutA = (HANDLE)BlkDesc->hDbgLogOutA;
   hLogOutB = (HANDLE)BlkDesc->hDbgLogOutB;
   *(PVOID*)&pVSprintf    = TGetProcedureAddress<PECURRENT>((PBYTE)LdrDesc->NtDllBase, "vsprintf");
   *(PVOID*)&pNtWriteFile = TGetProcedureAddress<PECURRENT>((PBYTE)LdrDesc->NtDllBase, "NtWriteFile");
   return;
  }
 if(!hLogOutA && !hLogOutB)return;
 char Buffer[1025];
 va_start(args,MsgFmt);
 TEB* teb = NtCurrentTeb();                                                 
 int LenA = ST::Format(pVSprintf, Buffer, SharedUserData->SystemTime.High1Time,SharedUserData->SystemTime.LowPart, (DWORD)teb->ClientId.UniqueProcess, (DWORD)teb->ClientId.UniqueThread, ProcName); 
 int LenB = pVSprintf(&Buffer[LenA],MsgFmt,args);
 UINT DSize = LenA+LenB;
 Buffer[DSize++] = '\r';
 Buffer[DSize++] = '\n';
 va_end(args);
 IO_STATUS_BLOCK IoStatusBlock = {0};
 NTSTATUS stat;
 if(hLogOutA)stat = pNtWriteFile(hLogOutA,NULL,NULL,NULL,&IoStatusBlock,&Buffer,DSize,NULL,NULL);
 if(hLogOutB)stat = pNtWriteFile(hLogOutB,NULL,NULL,NULL,&IoStatusBlock,&Buffer,DSize,NULL,NULL);
}
static void  _fastcall LdrLogInit(SModDesc* ModDesc){MsgLogToLdr((char*)ModDesc, NULL);}  
//---------------------------------------------------------------------------

UINT  _fastcall SizeLoader32(void);
UINT  _fastcall SizeLoader64(void);
UINT  _fastcall ReadLoader32(PBYTE DstBuf, UINT BufSize);
UINT  _fastcall ReadLoader64(PBYTE DstBuf, UINT BufSize);
int   _fastcall GenerateBinLdr(void); 

//===========================================================================================================
