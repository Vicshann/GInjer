
/*
  Copyright (c) 2018 Victor Sheinmann, Vicshann@gmail.com

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
  to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
*/

#include "GlobalInjector.h"

//------------------------------------------------------------------------------------------------------------
enum EInjTypes {itPatch=0,itRemap};

// Configs
bool ForceTgtCon     = false; // Force a target process to display a Console for debug messages logging
bool ReceiveDbgLog   = true;  // Receive debug messages from the loader and injected modules
bool NormDllPaths    = true;  // Normalize paths from '\??\HarddiskVolumeX\' to 'C:\'
bool DirectInject    = true;  // Inject right from the Callback Thread to avoid suspending of a target Process/Thread   (Disabled in InjectType=1 for a target under a debugger)
bool DeepExeName     = false; // Search for exe named modules in all dirs up to root
bool UseMainThread   = false; // Works only partially when DirectInject is enabled 
UINT InjectType      = 0;     // 0-Inject by patching ntdll.dll; 1=Inject by remapping ntdll.dll
UINT DrvTimeout   = CBProcess::DefTimeout; 
UINT DrvAltitude  = CBProcess::DefAltitude; 
wchar_t DrvName[128];
wchar_t SrvName[128];
wchar_t MtxName[128];
wchar_t SrvDesc[128];
wchar_t PipeNam[128];

extern HANDLE hLogFile;
extern HANDLE hConsOut;

volatile HINSTANCE hInstance; 
SERVICE_STATUS_HANDLE hSvcStatus; 
BOOL IsRunOnWow64 = FALSE;
UINT GDirPathLen = 0;
CBProcess*  pro; 
CDrvLoader* drv;
CObjStack<SInjProcDesc>* ProcStack;
HANDLE hEvtProcStack;
HANDLE hEvtCloseA;
HANDLE hEvtCloseB;
HANDLE hWorkerTh;
HANDLE hDbgLogPipe;
HANDLE hHostLogPipe;
SNtDllDesc NtDllInfo;


SNameExtCfg DirExts[4] = {
 {0, L"DirName", 0, L"!ldr"},    // Everything from this directory will be loaded
 {1, L"DirLcl",  0, L"l"},       // Load contents only if it is on same path as EXE
 {0, L"DirGbl",  0, L"g"},       // Load contents on all paths backwards from EXE directory
 {0,0,0,0}
};

SNameExtCfg ModExts[5] = {       
 {mfBeforeLdr,  L"ExtBefore",  0, L"b"},      // Inject before loader   
 {mfAfterLdr,   L"ExtAfter",   0, L"a"},      // Inject after loader
 {mfModuleX32,  L"ExtX32",     0, L"d"},      // Injected DLL is for x32 system or WOW64(after system loader execution)
 {mfModuleX64,  L"ExtX64",     0, L"q"},      // Injected DLL is for X64 proceses or WOW64(before system loader execution)
 {0,0,0,0}
};

struct    // DIRECTORY: [LdrDirName] [LdrDirLcl|LdrDirGbl]
{
 WORD Flags;        // Represent Ext 
 int NameLen;
 wchar_t NameVal[NameExtSize*2];
} LdrDirNames[LdrDirNamesCnt];

struct    // MODULE:    [ProcessName|FolderName] [BeforeExt|AfterExt] [X32Ext|X64Ext]
{
 WORD Flags;        // Represent Ext 
 int ExtLen;
 wchar_t ExtVal[NameExtSize*2];
} ModuleExts[ModuleNamesCnt];

wchar_t  DrvPath[MAX_PATH];
wchar_t  StartUpDir[MAX_PATH];
wchar_t  GlobalDllDir[MAX_PATH];
//============================================================================================================
template <typename T> int _stdcall GetMainThreadInfo(DWORD ProcessId, DWORD* ThreadIdOut, UINT64* ThreadTebOut)
{
 SWOW64Ext::SYSTEM_PROCESS_INFORMATION<T>* pSysProcInf = NULL;
 DWORD DataSize = 0;
 for(DWORD BufSize=1024*1024;;BufSize *= 2)
  {
   if(pSysProcInf)VirtualFree(pSysProcInf, 0, MEM_RELEASE);
   pSysProcInf  = (SWOW64Ext::SYSTEM_PROCESS_INFORMATION<T>*)VirtualAlloc(NULL, BufSize, MEM_COMMIT, PAGE_READWRITE);
   if(!pSysProcInf)return -1;
   NTSTATUS res = 0;
   if(sizeof(T) > sizeof(DWORD))res = SWOW64Ext::QuerySystemInformation(SystemExtendedProcessInformation, pSysProcInf, BufSize, &DataSize);  // Note: This process is WOW64. Normal NtQuerySystemInformation returns truncated pointers
     else res = NtQuerySystemInformation(SystemProcessInformation, pSysProcInf, BufSize, &DataSize);   // NOTE: Rereading everything again is not fast
   if(STATUS_SUCCESS == res)break;
   if(res != STATUS_INFO_LENGTH_MISMATCH){DBGMSG("QuerySystemInformation failed: %08X",res); return -2;}    
  }
 SWOW64Ext::SYSTEM_EXTENDED_THREAD_INFORMATION<T>* LastThread = NULL;
 for(SWOW64Ext::SYSTEM_PROCESS_INFORMATION<T>* pCurProc = pSysProcInf;;pCurProc = (SWOW64Ext::SYSTEM_PROCESS_INFORMATION<T>*)((PBYTE)pCurProc + pCurProc->NextEntryOffset))
  {       
   DBGMSG("Process: ID=%08X, Name=%ls",(DWORD)pCurProc->UniqueProcessId, ((PVOID)pCurProc->ImageName.Buffer)?((PVOID)pCurProc->ImageName.Buffer):(L""));
   if((DWORD)pCurProc->UniqueProcessId == ProcessId)
    {
     SWOW64Ext::SYSTEM_EXTENDED_THREAD_INFORMATION<T>* Threads = (SWOW64Ext::SYSTEM_EXTENDED_THREAD_INFORMATION<T>*)&pCurProc->Threads;
     if(pCurProc->NumberOfThreads)LastThread = &Threads[0];
	 for(UINT idx=0;idx < pCurProc->NumberOfThreads;idx++)       // First in the list is always a first thread of a process?
      {
       SWOW64Ext::SYSTEM_EXTENDED_THREAD_INFORMATION<T>* CurThread = &Threads[idx];
       UINT64 TebAddr   = CurThread->TebBase;
       UINT64 Win32Addr = CurThread->Win32StartAddress;
       UINT64 StartAddr = CurThread->ThreadInfo.StartAddress;    // RtlUserThreadStart
       UINT64 StackBase = CurThread->StackBase;
       DBGMSG("Thread: ID=%08X, TebAddr=%08X%08X, StackBase=%08X%08X, StartAddr=%08X%08X, Win32Addr=%08X%08X, CreateTime=%08X%08x",(DWORD)CurThread->ThreadInfo.ClientId.UniqueThread,
                                                                     (DWORD)(TebAddr   >> 32), (DWORD)TebAddr,
                                                                     (DWORD)(StackBase >> 32), (DWORD)StackBase,
                                                                     (DWORD)(StartAddr >> 32), (DWORD)StartAddr,
                                                                     (DWORD)(Win32Addr >> 32), (DWORD)Win32Addr,
                                                                     CurThread->ThreadInfo.CreateTime.HighPart, CurThread->ThreadInfo.CreateTime.LowPart);
       if(CurThread->ThreadInfo.CreateTime.QuadPart < LastThread->ThreadInfo.CreateTime.QuadPart)LastThread = CurThread;
      }
     break;
    }
   if(!pCurProc->NextEntryOffset)break;
  }      
 if(ThreadIdOut)*ThreadIdOut = (LastThread)?((DWORD)LastThread->ThreadInfo.ClientId.UniqueThread):(0);
 if(ThreadTebOut)*ThreadTebOut = (LastThread)?(LastThread->TebBase):(0);
 VirtualFree(pSysProcInf, 0, MEM_RELEASE);   
 return 0;
}
//------------------------------------------------------------------------------------------------------------
void _stdcall BuildNameExts(void)
{
 lstrcatW(LdrDirNames[0].NameVal, DirExts[0].Value); lstrcatW(LdrDirNames[0].NameVal, DirExts[1].Value); LdrDirNames[0].Flags = DirExts[1].Flags; LdrDirNames[0].NameLen = lstrlenW(LdrDirNames[0].NameVal);
 lstrcatW(LdrDirNames[1].NameVal, DirExts[0].Value); lstrcatW(LdrDirNames[1].NameVal, DirExts[2].Value); LdrDirNames[1].Flags = DirExts[2].Flags; LdrDirNames[1].NameLen = lstrlenW(LdrDirNames[1].NameVal);
 for(int ctr=0;ctr < ModuleNamesCnt;ctr++)
  {
   SNameExtCfg* CfgA = &ModExts[2+((ctr>>0)&1)];
   SNameExtCfg* CfgB = &ModExts[0+((ctr>>1)&1)];
   ModuleExts[ctr].ExtVal[0] = '.';     // Ext separator
   ModuleExts[ctr].ExtVal[1] = 0;
   lstrcatW(ModuleExts[ctr].ExtVal, CfgB->Value);
   lstrcatW(ModuleExts[ctr].ExtVal, CfgA->Value);
   ModuleExts[ctr].Flags = CfgA->Flags | CfgB->Flags;
   ModuleExts[ctr].ExtLen = lstrlenW(ModuleExts[ctr].ExtVal);
   DBGMSG("Idx=%.2u, Flags=%04X, Value=%ls",ctr, ModuleExts[ctr].Flags, &ModuleExts[ctr].ExtVal); 
  }  
}
//------------------------------------------------------------------------------------------------------------
int _stdcall PathStepBack(PWSTR Path, int PathLenChr=0)
{
 if(!PathLenChr)PathLenChr = lstrlenW(Path);
 PathLenChr--;
 if((Path[PathLenChr] == '/')||(Path[PathLenChr] == '\\'))PathLenChr--;
 for(;PathLenChr >= 0;PathLenChr--)
  {
   WCHAR val = Path[PathLenChr];
   if((val == '/')||(val == '\\'))return PathLenChr+1;   // Split
   if((val == ':')||(val == '?'))return -1;  // No more path
  }
 return -2;
}
//------------------------------------------------------------------------------------------------------------
PWSTR _stdcall SkipToPathDelim(PWSTR Path)
{
 while((*Path=='/')||(*Path=='\\'))Path++;   // Skip at beginning if any
 while((*Path!='/')&&(*Path!='\\') && *Path)Path++; 
 return Path;
}
//------------------------------------------------------------------------------------------------------------
int _stdcall OpenFileOrDirectory(PWSTR Path, bool IsDir, HANDLE* OutHndl, int PathLenChr=0)   // Path must start with "\\??\\"  (Put in instead of '\\Device\\' in '\\Device\\HarddiskVolume1\\')
{
 HANDLE hret = NULL;
 UNICODE_STRING PathStr;
 IO_STATUS_BLOCK IoStatusBlock = {0};
 OBJECT_ATTRIBUTES ObjAttrs = {0};

 DBGMSG("Path: %ls",Path);
 if(!PathLenChr)PathLenChr = lstrlenW(Path);
 PathStr.Buffer = Path;
 PathStr.Length = PathLenChr*sizeof(WCHAR);
 PathStr.MaximumLength = PathStr.Length+sizeof(WCHAR);

 ObjAttrs.Length = sizeof(OBJECT_ATTRIBUTES);
 ObjAttrs.Attributes = OBJ_CASE_INSENSITIVE;
 ObjAttrs.RootDirectory = 0;
 ObjAttrs.SecurityDescriptor = NULL;
 ObjAttrs.SecurityQualityOfService = NULL;
 ObjAttrs.ObjectName = &PathStr;
                                                                        
 ULONG OpenOpts = ((IsDir)?(FILE_DIRECTORY_FILE):(FILE_NON_DIRECTORY_FILE))|FILE_SYNCHRONOUS_IO_NONALERT;    
 ACCESS_MASK Access = ((IsDir)?(FILE_LIST_DIRECTORY):(FILE_READ_DATA))|STANDARD_RIGHTS_READ|SYNCHRONIZE;   // FILE_TRAVERSE              // NOTE: Do not specify FILE_READ_DATA, FILE_WRITE_DATA, FILE_APPEND_DATA, or FILE_EXECUTE when you create or open a directory.
 NTSTATUS res = NtOpenFile(&hret, Access, &ObjAttrs, &IoStatusBlock, FILE_SHARE_READ, OpenOpts);     // Is NtQueryAttributesFile still unreliable?
 if(res){DBGMSG("Failed with: %08X",res); return -1;}
 if(OutHndl)*OutHndl = hret;
   else CloseHandle(hret);
 DBGMSG("Done");
 return 0;
}
//------------------------------------------------------------------------------------------------------------
int _stdcall GetModulesFromDirectory(HANDLE hDir, DWORD BaseFlg, PWSTR DirRoot, UINT DirRootLen, CModPathArr* ModArr, PVOID NameBuf, UINT NameBufLen)
{
 IO_STATUS_BLOCK IoStatus = {0};
 NTSTATUS res = NtQueryDirectoryFile(hDir,NULL,NULL,NULL,&IoStatus,NameBuf,NameBufLen,FileNamesInformation,FALSE,NULL,TRUE);
 if(res){DBGMSG("Failed with: %08X",res); return -1;}   
          
 int Total = 0;
 for(FILE_NAMES_INFORMATION* FNameRec = (FILE_NAMES_INFORMATION*)NameBuf;FNameRec;FNameRec=(FILE_NAMES_INFORMATION*)&((PBYTE)FNameRec)[FNameRec->NextEntryOffset])
  {
   if(!((FNameRec->FileNameLength == 2)&&(FNameRec->FileName[0]=='.')) && !((FNameRec->FileNameLength == 4)&&(*(PDWORD)&FNameRec->FileName==0x002E002E)))
    {
     UINT FNameLenChr = FNameRec->FileNameLength/sizeof(WCHAR);
     PWSTR FExt = GetFileExt(FNameRec->FileName, FNameLenChr);
     for(int ctr=0;ctr < ModuleNamesCnt;ctr++)    // Check modules with name as containing directory
      {
       if(!NSTR::IsStrEqualIC(FExt, &ModuleExts[ctr].ExtVal[1], ModuleExts[ctr].ExtLen-1))continue;      
       SPathHandleDescr Obj;
       Obj.Flags  = BaseFlg|ModuleExts[ctr].Flags;
       Obj.hFSObj = NULL;
       PWSTR FName = Obj.Path.Assign(NULL, DirRootLen+FNameLenChr+1);    // No terminating 0
       lstrcpyW(FName, DirRoot);
       lstrcpynW(&FName[DirRootLen+1], FNameRec->FileName, FNameLenChr+1);
       FName[DirRootLen] = '\\';
       if(OpenFileOrDirectory(FName, false, &Obj.hFSObj, Obj.Path.Count()) >= 0)
        {
         Total++;
         if(ModArr)
          {
           if(NormDllPaths)Obj.SetDosPathByHandle(Obj.Path.c_data(), Obj.Path.Count());  
           ModArr->Add(&Obj);
           memset(&Obj,0,sizeof(Obj));  // Prevent Obj.Path from being released on destruction of Obj 
          }
        }
       break;
      }
    }
   if(!FNameRec->NextEntryOffset)break;
  }
 return Total;
}
//------------------------------------------------------------------------------------------------------------
// ProcPath must be large enough to contain file name as its directory name + ext
int _stdcall GetKnownModulesFromPath(PWSTR ProcPath, CModPathArr* ModArr, int PathLenChr=0)    // Contents of 'Path' buffer will be corrupted 
{
 wchar_t ProcName[MAX_PATH];    // Is enough?
 CWStrBuf PathBuf;
 int TotalCtr = 0;
 if(!ProcPath)return 0;
 if(!PathLenChr)PathLenChr = lstrlenW(ProcPath);
 DBGMSG("Path %u: %ls", PathLenChr, ProcPath);
 PathBuf.Assign(NULL, PathLenChr*2); // +Extra space to contain module name as its directory
 lstrcpynW(PathBuf.c_data(), ProcPath, PathLenChr+1);
 PWSTR Path = PathBuf.c_data();
 Path = SkipToPathDelim(Path);     // Skip '//' to first '?'
 Path = SkipToPathDelim(Path);     // Skip 'HarddiskVolumeX'
 int BaseOffsetChr = (Path - PathBuf.c_data())+1; 
 Path = PathBuf.c_data();
 UINT  FNamBufLen  = 0x10000; // 64k (~120 modules)
 PVOID FNameBuf    = NULL;
 DWORD ProcessRoot = mfModOnRoot;
 PWSTR ProcNameFirst = GetFileName(Path);  // Temporary!
 if(ProcNameFirst != Path)lstrcpynW(ProcName, ProcNameFirst, countof(ProcName));       // If path passed with a Process name  (Directories passed as 'Directory\\')  
   else ProcNameFirst - NULL;
 for(int PathLenLeft=PathLenChr;PathLenLeft >= BaseOffsetChr;PathLenLeft = PathStepBack(Path, PathLenLeft))   // '>=' include root dir, '>' - no root dir
  {  
   bool NFirst = (PathLenLeft == PathLenChr)&&(Path[PathLenLeft-1]!='/')&&(Path[PathLenLeft-1]!='\\');    // Initial path with a Process name
   if((NFirst || DeepExeName) && ProcNameFirst) 
    {
     int Offset = PathLenLeft;
     if(!NFirst)Offset += NSTR::StrCopy(&Path[Offset], ProcName);
     for(int ctr=0;ctr < ModuleNamesCnt;ctr++)    // Check modules with a target process` name
      {
       HANDLE HVal = NULL;
       UINT   PLen = Offset + ModuleExts[ctr].ExtLen;
       lstrcpyW(&Path[Offset], ModuleExts[ctr].ExtVal);
       if(OpenFileOrDirectory(Path, false, &HVal, PLen) >= 0)
        {
         TotalCtr++; 
         if(ModArr)
          {
           SPathHandleDescr* Obj = ModArr->Add(NULL);
           Obj->Flags  = ProcessRoot|ModuleExts[ctr].Flags;
           Obj->hFSObj = HVal;
           if(NormDllPaths)Obj->SetDosPathByHandle(Path, PLen); 
             else  Obj->Path.Assign(Path, PLen)[PLen] = 0;    // No terminating 0
          }
           else if(HVal)CloseHandle(HVal);
        }
      }
     if(NFirst)PathLenLeft = (ProcNameFirst - Path);   // Without a process name now  
    }
   
   if(PathLenLeft > BaseOffsetChr)  // Root dir have no name (Only !ldrg or !ldrl will be searched on root)
   {
   int DEndPos = PathLenLeft-2;    // To point to a last char of a dir name
   while((DEndPos >= BaseOffsetChr)&&(Path[DEndPos]!='/')&&(Path[DEndPos]!='\\'))DEndPos--;  // Until dir name begin
   int DirNameLen = PathLenLeft-(++DEndPos+1); 
   lstrcpynW(&Path[PathLenLeft], &Path[DEndPos], DirNameLen+1);
   for(int ctr=0;ctr < ModuleNamesCnt;ctr++)    // Check modules with name as containing directory
    {
     HANDLE HVal = NULL;
     UINT   PLen = PathLenLeft + DirNameLen + ModuleExts[ctr].ExtLen;
     lstrcpyW(&Path[PathLenLeft+DirNameLen], ModuleExts[ctr].ExtVal);
     if(OpenFileOrDirectory(Path, false, &HVal, PLen) >= 0)
      {
       TotalCtr++; 
       if(ModArr)
        {
         SPathHandleDescr* Obj = ModArr->Add(NULL);
         Obj->Flags  = ProcessRoot|ModuleExts[ctr].Flags;
         Obj->hFSObj = HVal;
         if(NormDllPaths)Obj->SetDosPathByHandle(Path, PLen); 
           else Obj->Path.Assign(Path, PLen)[PLen] = 0;    // No terminating 0
        }
         else if(HVal)CloseHandle(HVal);
      }
    }
   }

   for(int ctr=0;ctr < LdrDirNamesCnt;ctr++)   // Check Directories
    {
     if(!ProcessRoot && LdrDirNames[ctr].Flags)continue;  // Skip local folders on non root paths
     HANDLE HVal = NULL;
     UINT   PLen = PathLenLeft + LdrDirNames[ctr].NameLen;
     lstrcpyW(&Path[PathLenLeft], LdrDirNames[ctr].NameVal);
     if(OpenFileOrDirectory(Path, true, &HVal, PLen) >= 0)
      {
       TotalCtr++;     // Count only the directory itself
       if(ModArr)
        {
         if(!FNameBuf)FNameBuf = VirtualAlloc(NULL,FNamBufLen,MEM_COMMIT,PAGE_READWRITE);
         GetModulesFromDirectory(HVal, ProcessRoot, Path, PLen, ModArr, FNameBuf, FNamBufLen); 
        }
       if(HVal)CloseHandle(HVal);
      }
    } 
   ProcessRoot = 0; 
  }

 if(GDirPathLen && *GlobalDllDir)      // Read modules from a Global Directory
  {
   HANDLE HVal = NULL;
   if(OpenFileOrDirectory(GlobalDllDir, true, &HVal, GDirPathLen) >= 0)
    {       
     if(!FNameBuf)FNameBuf = VirtualAlloc(NULL,FNamBufLen,MEM_COMMIT,PAGE_READWRITE);
     int tot = GetModulesFromDirectory(HVal, 0, GlobalDllDir, GDirPathLen, ModArr, FNameBuf, FNamBufLen); 
     if(tot > 0)TotalCtr += tot;      
     if(HVal)CloseHandle(HVal);
    }
  }

 if(FNameBuf)VirtualFree(FNameBuf,0,MEM_RELEASE); 
 DBGMSG("Known objects found: %u", TotalCtr);
 return TotalCtr;
}
//------------------------------------------------------------------------------------------------------------
bool _fastcall IsModNameMatchProcessName(PWSTR ProcName, CWStrBuf* ModName)
{
 DBGMSG("ProcName=%ls, ModName=%ls", ProcName, ModName->c_data());
 PWSTR MExt = GetFileExt(ModName->c_data(), ModName->Count()); 
 if(!*MExt)return false;  // No Ext!
 PWSTR FNam = GetFileName(ModName->c_data(), ModName->Count()); 
 if(FNam == ModName->c_data())return false;  // No Name!
 int Len = (--MExt - FNam);
 DBGMSG("Len=%i, ProcName=%ls, FNam=%ls", Len, ProcName, FNam);
 if(Len < 0)return false;  // No Ext!
 return NSTR::IsStrEqualIC(ProcName, FNam, Len);
}
//------------------------------------------------------------------------------------------------------------
int __stdcall GatherModuleInfoAndFlags(SInjProcDesc* Desc, CModPathArr* ModArr, DWORD* RequiredMem, bool IsTgtWow64, bool IsSysX64)    
{
 UINT TotalX32 = 0;
 UINT TotalX64 = 0;
 BYTE Buffer[0x400];

 *RequiredMem   = sizeof(SBlkDesc);
 PWSTR ProcName = GetFileName(Desc->ProcPath.c_data(), Desc->ProcPath.Count());
 for(int ctr=0,tot=ModArr->Count();ctr < tot;ctr++)
  {
   SPathHandleDescr* Obj = ModArr->Get(ctr);
   if(!Obj->hFSObj)continue;
   DWORD Result;
   SetFilePointer(Obj->hFSObj,0,NULL,FILE_BEGIN);
   if(!ReadFile(Obj->hFSObj, &Buffer, sizeof(Buffer), &Result, NULL) || (sizeof(Buffer) != Result)){CloseHandle(Obj->hFSObj); Obj->hFSObj=NULL; Obj->Flags=0; continue;};
   DOS_HEADER *DosHdr = (DOS_HEADER*)&Buffer;
   WIN_HEADER<PECURRENT> *WinHdr = (WIN_HEADER<PECURRENT>*)&(((BYTE*)DosHdr)[DosHdr->OffsetHeaderPE]);
   Obj->Flags |= WinHdr->OptionalHeader.MajImageVer;
   Obj->Flags &= ~(mfModuleX32|mfModuleX64);
   Obj->Flags |= (WinHdr->OptionalHeader.Magic == 0x020B)?mfModuleX64:mfModuleX32;   
   if(
       ((Obj->Flags & mfLocalPath) && !(Obj->Flags & mfModOnRoot)) ||                   // This module need to be loaded only from initial dir
       (!IsSysX64  && (Obj->Flags & mfModuleX64)) ||                                    // Impossible :)
       (IsTgtWow64 && (Obj->Flags & mfModuleX64) && !(Obj->Flags & mfModXAny)) ||       // Do not load a X64 module into WOW64 process if it is not marked as mfModXAny
       ((Obj->Flags & mfSameName) && !IsModNameMatchProcessName(ProcName, &Obj->Path))  // This module must have matching name with a target process
     ) 
       {CloseHandle(Obj->hFSObj); Obj->hFSObj=NULL; Obj->Flags=0; DBGMSG("Module skipped: Flags=%08X, Path=%ls", Obj->Flags, Obj->Path.c_data()); continue;};      // Close and invalidate this module
                                                                             
   *RequiredMem = AlignP2Frwd(*RequiredMem + ((Obj->Path.Count()+1)*sizeof(WCHAR)) + sizeof(SModDesc),LDR_STRUCT_ALIGN);                                   
   if(Obj->Flags & mfReflLoad)*RequiredMem = AlignP2Frwd(*RequiredMem + GetFileSize(Obj->hFSObj, NULL),LDR_STRUCT_ALIGN);    
   if(Obj->Flags & mfModuleX32)TotalX32++;
   if(Obj->Flags & mfModuleX64)TotalX64++;                
   DBGMSG("Module ready: Flags=%08X, Path=%ls", Obj->Flags, Obj->Path.c_data());
  }

 bool PresentX32 = (!IsRunOnWow64 || IsTgtWow64) && TotalX32;
 bool PresentX64 = IsRunOnWow64 && (TotalX64 || TotalX32);   // On x64 system it always starts in x64 ntdll.dll
 if(PresentX32)*RequiredMem = AlignP2Frwd(*RequiredMem + SizeLoader32(),LDR_STRUCT_ALIGN);
 if(PresentX64)*RequiredMem = AlignP2Frwd(*RequiredMem + SizeLoader64(),LDR_STRUCT_ALIGN);
 DBGMSG("Modules to inject: TotalX32=%u, TotalX64=%u", TotalX32, TotalX64);
 return TotalX32+TotalX64;
}
//------------------------------------------------------------------------------------------------------------
int _stdcall CreateSharedSecView(HANDLE hTgtProcess, UINT64 RemoteAddr, UINT Size, PVOID* SecLocAddr, UINT64* SecRemAddr)
{
 OBJECT_ATTRIBUTES ObjAttrs = {0};
 ObjAttrs.Length = sizeof(OBJECT_ATTRIBUTES); 

 HANDLE hSec = NULL;
 LARGE_INTEGER MaxSize;
 MaxSize.QuadPart = Size;
 NTSTATUS stat = NtCreateSection(&hSec, SECTION_ALL_ACCESS, &ObjAttrs, &MaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
 if(stat){DBGMSG("CreateSection failed with %08X",stat); return -1;}
 SIZE_T ViewSize = 0;
 *SecRemAddr = NULL;
 if(RemoteAddr && IsRunOnWow64)     // Need to place at exact address on x64 system
  {
   DWORD64 ViewLen = 0;
   *SecRemAddr = RemoteAddr;
   stat = SWOW64Ext::MapViewOfSection(hSec, hTgtProcess, SecRemAddr, 0, 0, NULL, &ViewLen, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);  
  }
   else         // Need any address(within 2 GB) or the system is native x32
   {
    PVOID AddrVal = (PVOID)RemoteAddr;                         
    stat = NtMapViewOfSection(hSec, hTgtProcess, &AddrVal, 1, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);   // ZeroBits: 0 gives us full 64 bit addresses and 1 gives us the lower 2GB
    *SecRemAddr = (UINT64)AddrVal;
   }   
 if(stat){DBGMSG("Remote MapViewOfSection failed with %08X",stat); return -2;}
 *SecLocAddr = NULL;
 stat = NtMapViewOfSection(hSec, GetCurrentProcess(), SecLocAddr, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);    
 CloseHandle(hSec);
 if(stat){DBGMSG("Local MapViewOfSection failed with %08X",stat); return -3;}
 DBGMSG("SecLocAddr=%p, SecRemAddr=%08X%08X", *SecLocAddr, (DWORD)(*SecRemAddr >> 32), (DWORD)*SecRemAddr);
 return 0;
}
//------------------------------------------------------------------------------------------------------------
SBlkDesc* _stdcall WriteSharedData(CModPathArr* ModArr, PBYTE Addr, long Size, UINT64 RemoteAddr, bool TgtWow64)
{
 SBlkDesc* Desc = (SBlkDesc*)Addr;
 UINT DataOffset = sizeof(SBlkDesc);
 memset(Desc,0,sizeof(SBlkDesc));
 UINT CntMod32 = 0;
 UINT CntMod64 = 0;
 for(UINT ctr=0;ctr < ModArr->Count();ctr++)
  {
   SPathHandleDescr* Mod = ModArr->Get(ctr);
   if(Mod->Flags & mfModuleX32)CntMod32++;
   if(Mod->Flags & mfModuleX64)CntMod64++;
  }                                 
 if(!CntMod32 && !CntMod64){DBGMSG("No modules to load!"); return NULL;}
 bool PresentX32 = (!IsRunOnWow64 || TgtWow64) && CntMod32;
 bool PresentX64 = IsRunOnWow64 && (CntMod64 || CntMod32);   // On x64 system it always starts in x64 ntdll.dll
 if(PresentX32)    
  { 
   UINT LdrSize = SizeLoader32();
   if(!LdrSize){DBGMSG("x32 loader is empty!"); return NULL;}
   ReadLoader32(&Addr[DataOffset], LdrSize);
   Desc->LdrDesc32.LdrProcAddr = RemoteAddr + DataOffset;
   DBGMSG("Added x32 loader code: %08X, %08X",(DWORD)(RemoteAddr+DataOffset),LdrSize);
   DataOffset = AlignP2Frwd(DataOffset+LdrSize,LDR_STRUCT_ALIGN);  
  }
 if(PresentX64)    
  { 
   UINT  LdrSize = SizeLoader64();
   if(!LdrSize){DBGMSG("x64 loader is empty!"); return NULL;}
   ReadLoader64(&Addr[DataOffset], LdrSize);
   Desc->LdrDesc64.LdrProcAddr = RemoteAddr + DataOffset;   
   DBGMSG("Added x64 loader code: %08X, %08X",(DWORD)(RemoteAddr+DataOffset),LdrSize);
   DataOffset = AlignP2Frwd(DataOffset+LdrSize,LDR_STRUCT_ALIGN);
  }
 if(PresentX32)    
  { 
   Desc->LdrDesc32.Flags = dfNotEmpty;
   if(TgtWow64)Desc->LdrDesc32.Flags |= dfThisIsWow64;
   if(NtDllInfo.IsX32LdrInitStdcall)Desc->LdrDesc32.Flags |= dfStdcallLdrpInit; 
   Desc->LdrDesc32.AddrOfLdrpInit      = NtDllInfo.NtDllBase32 + NtDllInfo.OffsLdrpInitialize32;
   Desc->LdrDesc32.LdrpInitRetAddr     = NtDllInfo.NtDllBase32 + NtDllInfo.OffsLdrpInitRet32;     // Original return address from LdrpInitialize 
   Desc->LdrDesc32.AddrOfLdrInitThunk  = NtDllInfo.NtDllBase32 + NtDllInfo.OffsLdrInitializeThunk32;  
  }
 if(PresentX64)    
  { 
   Desc->LdrDesc64.Flags = dfNotEmpty;
   if(TgtWow64)Desc->LdrDesc64.Flags |= dfThisIsWow64; 
   Desc->LdrDesc64.AddrOfLdrpInit      = NtDllInfo.NtDllBase64 + NtDllInfo.OffsLdrpInitialize64;
   Desc->LdrDesc64.LdrpInitRetAddr     = NtDllInfo.NtDllBase64 + NtDllInfo.OffsLdrpInitRet64;     // Original return address from LdrpInitialize 
   Desc->LdrDesc64.AddrOfLdrInitThunk  = NtDllInfo.NtDllBase64 + NtDllInfo.OffsLdrInitializeThunk64;  
  }

 Size -= DataOffset;
 DWORD   PrevSize = 0;
 Desc->ModDescLstOffs = DataOffset;  
 for(UINT ctr=0;ctr < ModArr->Count();ctr++)
  {
   SPathHandleDescr* Mod = ModArr->Get(ctr);
   if(!Mod->Flags || !Mod->hFSObj || !Mod->Path.Count()){DBGMSG("Module %u is not defined!",ctr); continue;}
   UINT ModRecSize = AlignP2Frwd(sizeof(SModDesc) + ((Mod->Path.Count()+1) * sizeof(WCHAR)),LDR_STRUCT_ALIGN);    // Module body alignment
   SModDesc* Desc  = (SModDesc*)&Addr[DataOffset];
   if(Mod->Flags & mfReflLoad)
    {
     DWORD Result   = 0;
     DWORD FileSize = GetFileSize(Mod->hFSObj, NULL);
     if(FileSize < sizeof(DOS_HEADER)){DBGMSG("Module %u is empty!",ctr); continue;}
     SetFilePointer(Mod->hFSObj,0,NULL,FILE_BEGIN);
     PBYTE PEMod = &Addr[DataOffset+ModRecSize];
     if(!ReadFile(Mod->hFSObj, PEMod, FileSize, &Result, NULL) || (FileSize != Result)){DBGMSG("Failed to read module %u: %u - %ls",ctr,GetLastError(),Mod->Path.c_data()); continue;};   
     Desc->ModSize    = GetImageSize(PEMod);    
     Desc->ModEPOffs  = GetModuleEntryOffset(PEMod, true);
     Desc->ModRawSize = FileSize;
     Desc->ModuleBase = RemoteAddr + DataOffset + ModRecSize;
     ModRecSize = AlignP2Frwd(ModRecSize+FileSize,LDR_STRUCT_ALIGN);  
     InjLdr::EncryptModuleParts(PEMod, NULL, InjLdr::mfRawMod|fmCryHdr|fmCryImp|fmCryExp|fmCryRes);   // Code and data is not encrypted
     DBGMSG("Reflective Module EP=%08X: %ls",(DWORD)(Desc->ModuleBase+Desc->ModEPOffs),&Mod->Path.c_data()[4]); 
    }
     else Desc->ModuleBase = Desc->ModRawSize = Desc->ModEPOffs = Desc->ModSize = 0;   
     
   lstrcpynW(Desc->ModulePath, Mod->Path.c_data(), Mod->Path.Count()+1);        //   lstrcpynW(Desc->ModulePath, &Mod->Path.c_data()[4], Mod->Path.Count()-4+1);   // Skips /??/
   if(!NormDllPaths)Desc->ModulePath[1] = '\\';           // LdrLoadDll accepts only '\\?\' but not '\??\'
   Desc->PrevSize = PrevSize;      
   Desc->Flags    = Mod->Flags;
   Desc->PathSize = Mod->Path.Count();   // In chars, not including 0
   Desc->NextOffs = ((ctr+1) < ModArr->Count())?(ModRecSize):(0);   
   DataOffset += ModRecSize;
   PrevSize    = ModRecSize; 
  }
 DBGMSG("Done");
 return Desc;
}
//------------------------------------------------------------------------------------------------------------
int _stdcall SetHookOfNtDll(SBlkDesc* BlkHdr, SInjProcDesc* ProcDesc)
{
 bool Remapped = false;
 BYTE Patch[]  = {0x50,0x68,0,0,0,0,0xC3};    // push eax; push XXXXXXXX; ret    // Target block is in 2GB
 *(PDWORD)&Patch[2] = (IsRunOnWow64)?(BlkHdr->LdrDesc64.LdrProcAddr):(BlkHdr->LdrDesc32.LdrProcAddr);
 DBGMSG("Enter: InjType=%u", ProcDesc->InjType);
 if(ProcDesc->InjType == itRemap)
  {
   DBGMSG("Remapping ntdll.dll");
   if(IsRunOnWow64)
    {                                                                    
     NTSTATUS stat = SWOW64Ext::UnmapViewOfSection(ProcDesc->hProcess, NtDllInfo.NtDllBase64);
     if(!stat)
      {
       PVOID  SecLocAddr = NULL; 
       UINT64 SecRemAddr = NULL;
       DBGMSG("NtDllBase=%08X%08X, NtDllSize=%08X", (DWORD)(NtDllInfo.NtDllBase64 >> 32), (DWORD)NtDllInfo.NtDllBase64, (DWORD)NtDllInfo.NtDllSize64);
       if(CreateSharedSecView(ProcDesc->hProcess, NtDllInfo.NtDllBase64, NtDllInfo.NtDllSize64, &SecLocAddr, &SecRemAddr) >= 0)
        {
         SWOW64Ext::memcpy((UINT64)SecLocAddr, NtDllInfo.NtDllBase64, NtDllInfo.NtDllSize64);   // Copy NtDll.dll    // Is all pages readable?   // Do a separate function?
         SWOW64Ext::memcpy((UINT64)SecLocAddr + NtDllInfo.OffsLdrpInitPatch64, (DWORD64)&Patch, sizeof(Patch));  
         if(SecLocAddr)NtUnmapViewOfSection(GetCurrentProcess(), SecLocAddr);
         Remapped = true;
        }
      }
       else {DBGMSG("Failed to unmap %08X%08X: %08X", (DWORD)(NtDllInfo.NtDllBase64 >> 32), (DWORD)NtDllInfo.NtDllBase64, stat);}
    }
     else
      {
       NTSTATUS stat = NtUnmapViewOfSection(ProcDesc->hProcess, (PVOID)NtDllInfo.NtDllBase32);
       if(!stat)
        {
         PVOID  SecLocAddr = NULL; 
         UINT64 SecRemAddr = NULL;
         DBGMSG("NtDllBase=%08X, NtDllSize=%08X", (DWORD)NtDllInfo.NtDllBase32, (DWORD)NtDllInfo.NtDllSize32);
         if(CreateSharedSecView(ProcDesc->hProcess, NtDllInfo.NtDllBase32, NtDllInfo.NtDllSize32, &SecLocAddr, &SecRemAddr) >= 0)
          {
           memcpy((PBYTE)SecLocAddr, (PBYTE)NtDllInfo.NtDllBase32, NtDllInfo.NtDllSize32);   // Copy NtDll.dll    // Is all pages readable?  // Do a separate function?
           memcpy((PBYTE)SecLocAddr + NtDllInfo.OffsLdrpInitPatch32, &Patch, sizeof(Patch));  
           if(SecLocAddr)NtUnmapViewOfSection(GetCurrentProcess(), SecLocAddr); 
           Remapped = true;
          }
        }
         else {DBGMSG("Failed to unmap %08X%08X: %08X", (DWORD)(NtDllInfo.NtDllBase64 >> 32), (DWORD)NtDllInfo.NtDllBase64, stat);}
      }     
  }
 if((ProcDesc->InjType == itPatch) || !Remapped)    // Fallback to Patc if remapping is failed  // NOTE: Remapping may fail AFTER UnmapViewOfSection of ntdll.dll then a target process will crash anyway
  {
   DBGMSG("Patching ntdll.dll");
   if(IsRunOnWow64)      // All threads start as x64
    {     
     DWORD64 RegionSize  = sizeof(SNtDllDesc::OrigLdrInitializeThunk64);
     DWORD64 BaseAddress = NtDllInfo.NtDllBase64 + NtDllInfo.OffsLdrpInitPatch64;
     NTSTATUS stat = SWOW64Ext::ProtectVirtualMemory(ProcDesc->hProcess, &BaseAddress, &RegionSize, PAGE_EXECUTE_READWRITE, &BlkHdr->LdrDesc64.OldProtLdrInitThunk);
     if(stat){DBGMSG("ProtectVirtualMemory failed with %08X",stat); return -1;}  
     DWORD64 NumberOfBytesWritten = 0;
     stat = SWOW64Ext::WriteVirtualMemory(ProcDesc->hProcess, NtDllInfo.NtDllBase64 + NtDllInfo.OffsLdrpInitPatch64, &Patch, sizeof(Patch), &NumberOfBytesWritten);   
     if(stat){DBGMSG("WriteVirtualMemory failed with %08X",stat); return -2;}     // Restore protection?                           
    }
     else
      {
       SIZE_T RegionSize  = sizeof(SNtDllDesc::OrigLdrInitializeThunk32);
       PVOID  BaseAddress = (PVOID)(NtDllInfo.NtDllBase32 + NtDllInfo.OffsLdrpInitPatch32);
       NTSTATUS stat = NtProtectVirtualMemory(ProcDesc->hProcess, &BaseAddress, &RegionSize, PAGE_EXECUTE_READWRITE, &BlkHdr->LdrDesc32.OldProtLdrInitThunk);
       if(stat){DBGMSG("ProtectVirtualMemory failed with %08X",stat); return -3;} 
       SIZE_T NumberOfBytesWritten = 0;
       stat = NtWriteVirtualMemory(ProcDesc->hProcess, (PVOID)(NtDllInfo.NtDllBase32 + NtDllInfo.OffsLdrpInitPatch32), &Patch, sizeof(Patch), &NumberOfBytesWritten);   
       if(stat){DBGMSG("WriteVirtualMemory failed with %08X",stat); return -4;}     // Restore protection?                             
      }
  }

 memcpy(&BlkHdr->LdrDesc32.OrigLdrInitThunk, &NtDllInfo.OrigLdrInitializeThunk32, sizeof(BlkHdr->LdrDesc32.OrigLdrInitThunk));  // Move to 'WriteSharedData'?
 memcpy(&BlkHdr->LdrDesc64.OrigLdrInitThunk, &NtDllInfo.OrigLdrInitializeThunk64, sizeof(BlkHdr->LdrDesc64.OrigLdrInitThunk));  // Move to 'WriteSharedData'?
 memcpy(&BlkHdr->CodeNtMapViewOfSection, &NtDllInfo.CodeNtMapViewOfSection, sizeof(BlkHdr->CodeNtMapViewOfSection));
 memcpy(&BlkHdr->CodeNtUnmapViewOfSection, &NtDllInfo.CodeNtUnmapViewOfSection, sizeof(BlkHdr->CodeNtUnmapViewOfSection));
 memcpy(&BlkHdr->LdrSystemDllInitBlock, &NtDllInfo.LdrSystemDllInitBlock, sizeof(BlkHdr->LdrSystemDllInitBlock));
 BlkHdr->AddrOfLdrSystemDllInitBlock = NtDllInfo.AddrOfLdrSystemDllInitBlock;
 if(ReceiveDbgLog)
  {
   HANDLE hOutA = NULL;
   if(IsValidHandle(hDbgLogPipe)){DuplicateHandle(GetCurrentProcess(), hDbgLogPipe, ProcDesc->hProcess, &hOutA, 0, FALSE, DUPLICATE_SAME_ACCESS); DBGMSG("Duplicated %u hDbgLogPipe: %p", GetLastError(), hOutA);} 
   BlkHdr->hDbgLogOutA = (UINT64)hOutA;
  }
 if(ForceTgtCon)
  {
   HANDLE hOutB = NULL;
   if(IsValidHandle(hConsOut)){DuplicateHandle(GetCurrentProcess(), hConsOut, ProcDesc->hProcess, &hOutB, 0, FALSE, DUPLICATE_SAME_ACCESS); DBGMSG("Duplicated %u hConsOut: %p", GetLastError(), hOutB);}   // Writing to it returns STATUS_UNSUCCESSFUL
   BlkHdr->hDbgLogOutB = (UINT64)hOutB;
  }
 DBGMSG("Done");
 return 0;
}
//------------------------------------------------------------------------------------------------------------
int _stdcall TryInjectProcess(SInjProcDesc* Desc)                 
{
 CModPathArr Array;   // Closes all handles on destruction
 DWORD RequiredMem   = 0;           // Will include all reflective modules
 BOOL  IsTargetWow64 = FALSE;
// __try               // Requires security_cookie
//  {
   if(!IsWow64Process(Desc->hProcess, &IsTargetWow64)){DBGMSG("Unknown process type!"); return -1;}
   if((GetKnownModulesFromPath(Desc->ProcPath.c_data(), &Array, Desc->ProcPath.Count()) <= 0) || !Array.Count()){DBGMSG("No modules to inject on the Process path"); return -1;}    // '\\??\\HarddiskVolume6\\'
   if(GatherModuleInfoAndFlags(Desc, &Array, &RequiredMem, IsTargetWow64, IsRunOnWow64) <= 0){DBGMSG("No modules to inject into the process"); return -2;} 
   DBGMSG("Required Memory: %08X", RequiredMem);                      
   PVOID  SecLocAddr  = NULL; 
   UINT64 SecRemAddr  = NULL;
   if(CreateSharedSecView(Desc->hProcess, 0, RequiredMem, &SecLocAddr, &SecRemAddr) < 0)return -2;
   SBlkDesc* BlkHdr = WriteSharedData(&Array, (PBYTE)SecLocAddr, RequiredMem, SecRemAddr, IsTargetWow64);
   if(!BlkHdr){DBGMSG("Failed to write shared data block!"); NtUnmapViewOfSection(GetCurrentProcess(), SecLocAddr); return -3;}
   if(SetHookOfNtDll(BlkHdr, Desc) < 0){DBGMSG("Failed to write ntdll hooks!"); NtUnmapViewOfSection(GetCurrentProcess(), SecLocAddr); return -4;}
   NtUnmapViewOfSection(GetCurrentProcess(), SecLocAddr); 
//  }
//   __except(EXCEPTION_EXECUTE_HANDLER){DBGMSG("Crashed!");} 
 DBGMSG("Done");
 return 0;
}
//------------------------------------------------------------------------------------------------------------
int  _stdcall AddNewProcessToStack(DWORD ProcessId, PWSTR ProcessImagePath, UINT PathLenChr)
{
 CHndl hThread;
 int InjType = InjectType;
 DWORD MainThreadId = 0;
 DWORD PrAccessFlg = PROCESS_VM_OPERATION|PROCESS_QUERY_INFORMATION;
 if(ReceiveDbgLog)PrAccessFlg |= PROCESS_DUP_HANDLE;     // Without this DuplicateHandle to target process will fail
 if(InjType == itPatch)PrAccessFlg |= PROCESS_VM_READ|PROCESS_VM_WRITE;  // For NtWriteVirtualMemory
 if(DirectInject && !UseMainThread)PrAccessFlg |= PROCESS_SUSPEND_RESUME;            // For NtSuspendProcess

 CHndl hProcess = OpenProcess(PrAccessFlg,FALSE,ProcessId);  
 if(hProcess.IsValid() && (InjType == itRemap)) 
  {
   BOOL TgtDebugged = FALSE;
   if(CheckRemoteDebuggerPresent(hProcess, &TgtDebugged) && TgtDebugged)  // If the target process is started by a debugger then unmapping its ntdll.dll will cause a deadlock in NtUnmapViewOfSection
    {
     DBGMSG("Target process %u is being debugged!",ProcessId);
     InjType = itPatch;    // Debuggers can`t operate after ntdll remapping
     PrAccessFlg |= PROCESS_VM_READ|PROCESS_VM_WRITE; 
     hProcess.Close();
     hProcess.Set(OpenProcess(PrAccessFlg,FALSE,ProcessId));   // Reopen it with new access rights
    }
  }                                    
 if(!hProcess){DBGMSG("Failed to open process %u: Code=%u, %ls",ProcessId,GetLastError(),ProcessImagePath); return -1;}
 DBGMSG("Opened process %u: %ls",ProcessId,ProcessImagePath);   // Is there are way to get the main thread ID from the driver without subscription to all thread events?

 if(UseMainThread)     // Suspends every new process(Main Thread) and checks its path in WorkerThread 
  {  
   UINT64 MainThreadTeb;
   int res = 0;
   if(IsRunOnWow64)res = GetMainThreadInfo<UINT64>(ProcessId, &MainThreadId, &MainThreadTeb);     // What is slower: Request full processes and threads list on each process creation or search paths to modules to inject?
     else res = GetMainThreadInfo<SIZE_T>(ProcessId, &MainThreadId, &MainThreadTeb);
   if(res < 0){DBGMSG("GetMainThreadInfo failed with %i",res); return -2;}
   DWORD ThAccessFlg = THREAD_QUERY_INFORMATION|THREAD_SUSPEND_RESUME;
#ifdef _DEBUG
   ThAccessFlg |= THREAD_GET_CONTEXT;  // |THREAD_SET_CONTEXT;
#endif
   hThread.Set(OpenThread(ThAccessFlg, FALSE, MainThreadId));     // No CONTEXT is avaliavle (:GetThreadContext will deadlock when called from the driver callback)
   if(!hThread){DBGMSG("Failed to open thread %u: Code=%u",MainThreadId,GetLastError()); return -3;}
   DBGMSG("Opened thread %u",MainThreadId);
  }
 
 if(DirectInject)     // Do full process path search here and try to inject
  {
   SInjProcDesc obj;
   obj.InjType = InjType;
   obj.Assign(hProcess, hThread, ProcessImagePath, PathLenChr);   // No main thread handle passed
   TryInjectProcess(&obj);       // The Main thread handle is not required for this
  }
   else      // Suspend the process without opening its main thread
    {
     if(hThread.IsValid()){ if(NTSTATUS stat = NtSuspendThread(hThread, NULL)){DBGMSG("Failed to suspend thread %u: Code=%08X", MainThreadId, stat); return -5;} }  // Suspend the thread to see its unmodified stack in debugger later(It is empty)   // NOTE: Requesting thread`s context here causes deadlock
       else { if(NTSTATUS stat = NtSuspendProcess(hProcess)){DBGMSG("Failed to suspend process %u: Code=%08X", ProcessId, stat); return -4;} }    // The process must be opened with PROCESS_SUSPEND_RESUME    
     SInjProcDesc obj;
     obj.InjType = InjType;
     obj.Assign(hProcess.Invalidate(), hThread.Invalidate(), ProcessImagePath, PathLenChr);   // No main thread handle passed
     ProcStack->PushObject(&obj);
     SetEvent(hEvtProcStack);
    }
 DBGMSG("Done");
 return 0;
}
//------------------------------------------------------------------------------------------------------------
//  At this point suspended threads report their context`s EIP pointing to RtlUserThreadStart but when resumed will continue their execution at LdrInitializeThunk
//   and will load all imported dlls before reaching RtlUserThreadStart
//
DWORD __stdcall WorkerThreadProc(LPVOID lpThreadParameter)
{
 OVERLAPPED DbgPipeOvr;
 HANDLE hPipeEvt = NULL;
 HANDLE HndlArr[2];
 UINT HndlCnt = 1;
 HndlArr[0] = hEvtProcStack; 
 BYTE MsgBuffer[1050];
 if(hHostLogPipe)
  {
   HndlCnt++; 
   HndlArr[1] = hPipeEvt = CreateEventW(NULL, FALSE, TRUE, NULL);    // The Event is left signaled and will trigger first WaitForMultipleObjects     
  }   
 while(DWORD WaitRes = WaitForMultipleObjects(HndlCnt, HndlArr, FALSE, INFINITE))    // 
  {
   if(WAIT_FAILED == WaitRes){DBGMSG("Wait failed with %u",GetLastError()); break;}
   if(WaitRes >= WAIT_ABANDONED_0)continue;
   UINT Index = WaitRes - WAIT_OBJECT_0;
   if(Index > 0)     // Process a debug pipe message
    {
     DWORD BytesReady = 0;
   //  ResetEvent(DbgPipeOvr.hEvent);
     GetOverlappedResult(hHostLogPipe, &DbgPipeOvr, &BytesReady, FALSE);  
     for(;;)
      {
       if(BytesReady){LOGTXT((char*)&MsgBuffer, BytesReady); }
       BytesReady = 0;
    //   ResetEvent(DbgPipeOvr.hEvent);
       memset(&DbgPipeOvr,0,sizeof(DbgPipeOvr));
       DbgPipeOvr.hEvent = hPipeEvt;
      // BOOL res = ReadFile(hHostLogPipe,&MsgBuffer,sizeof(MsgBuffer),&BytesReady,&DbgPipeOvr);
      // int err = GetLastError();
      // if(!res)break;
       if(!ReadFile(hHostLogPipe,&MsgBuffer,sizeof(MsgBuffer),&BytesReady,&DbgPipeOvr))break;
      }
     continue;
    }
   SInjProcDesc obj;
   if(!ProcStack->PopObject(&obj)){DBGMSG("Nothing!"); continue;}                    
   DBGMSG("Process: PrH=%08X, TrH=%08X, Path=%ls",obj.hProcess,obj.hMainThread,obj.ProcPath.c_data());
#ifdef _DEBUG
   if(obj.hMainThread)
    {
     DBGMSG("Reading context...");      // void RtlUserThreadStart(PTHREAD_START_ROUTINE BaseExecutionAddress, PVOID Context);
     UINT64 StartAddr = 0;
     UINT64 UserParam = 0;
     if(IsRunOnWow64)        // A WOW64 thread is in x64 space here so on x64 system a real StartAddress is always in RCX
      {
       SWOW64Ext::_CONTEXT64 ctx = {0};  
       ctx.ContextFlags = CONTEXT64_INTEGER | CONTEXT64_CONTROL; 
       NTSTATUS res = SWOW64Ext::GetContextThread(obj.hMainThread, &ctx);     
       if(!res){StartAddr = ctx.Rcx; UserParam = ctx.Rdx; DBGMSG("RIP: %08X%08X, RCX: %08X%08X, RDX: %08X%08X", (DWORD)(ctx.Rip >> 32), (DWORD)ctx.Rip,  (DWORD)(ctx.Rcx >> 32), (DWORD)ctx.Rcx,   (DWORD)(ctx.Rdx >> 32), (DWORD)ctx.Rdx);}
        else {DBGMSG("GetContextThread failed: %08X",res);}
      }
       else     // On x32 systems a real StartAddress is always in EAX
        {
#ifndef _AMD64_  
         CONTEXT ctx;
         ctx.ContextFlags = CONTEXT64_INTEGER; 
         NTSTATUS res = NtGetContextThread(obj.hMainThread, &ctx);  
         if(!res){StartAddr = ctx.Eax; UserParam = ctx.Ebx; DBGMSG("EIP: %08X, EAX: %08X, EBX: %08X", ctx.Eip, ctx.Eax, ctx.Ebx);}   // No other registers are used
          else {DBGMSG("GetContextThread failed: %08X",res);} 
#endif 
      }
     DBGMSG("StartAddr=%08X%08X, UserParam=%08X%08X",(DWORD)(StartAddr >> 32), (DWORD)StartAddr,   (DWORD)(UserParam >> 32), (DWORD)UserParam);
    }
#endif
   if(TryInjectProcess(&obj) < 0){DBGMSG("Failed to inject!");}  
   DBGMSG("Done with: PrH=%08X",obj.hProcess);                                    
   if(obj.hMainThread)ResumeThread(obj.hMainThread);     // If Thread is NULL then it is the target process has been suspended 
     else NtResumeProcess(obj.hProcess);
   obj.Close();
  }
 if(hPipeEvt)CloseHandle(hPipeEvt);
 CloseHandle(hWorkerTh);
 return 0;
}
//------------------------------------------------------------------------------------------------------------
// The HandlerRoutine function should return TRUE if it has finished processing the event. 
// If this function returns FALSE, then the next handler from the list for this console application will be used.
// Take note that the system launches HandlerRoutine in a separate thread, therefore, additional actions may be needed in order to ensure synchronization. 
// The application will be terminated once the handler returns
//
BOOL WINAPI ConHandlerRoutine(DWORD dwCtrlType)
{
 DBGMSG("Enter");
 switch (dwCtrlType)
  {
   case CTRL_C_EVENT:
   case CTRL_CLOSE_EVENT:
   case CTRL_LOGOFF_EVENT:    // Current user logs off   
   case CTRL_SHUTDOWN_EVENT:  // Computer is shutting down
     if(hEvtCloseA)
      {  
       hEvtCloseB = CreateEventW(NULL, TRUE, FALSE, NULL);
       SetEvent(hEvtCloseA);            // Is main thread is still alive there?
       if(hEvtCloseB)WaitForSingleObject(hEvtCloseB, INFINITE);     
      }
     DBGMSG("Exit");
     return TRUE;
  }
 DBGMSG("Fail");
 return FALSE;
}
//------------------------------------------------------------------------------------------------------------
int _stdcall UcbCallback(CBProcess::UCB_REQUEST_PARAMETERS* Params)
{     
 DBGMSG("Callback %u:",Params->Operation);
// DumpHexDataFmt((PBYTE)Params, sizeof(CBProcess::UCB_REQUEST_PARAMETERS));
 switch(Params->Operation)
  {
	case CBProcess::evProcessCreation:      // First thread is already created but not running yet and stays in kernel. Cycles counter is 0 but ntdll.dll(both for WOW64) is loaded
         DBGMSG("ProcCrt %u: ProcessId=%08X, ParentProcessId=%08X, CreatingProcessId=%08X, CreatingThreadId=%08X, FileOpenNameAvailable=%08X, ProcessName=%ls", Params->Operation,
          Params->Info.ProcessCrt.ProcessId,
          Params->Info.ProcessCrt.ParentProcessId,
          Params->Info.ProcessCrt.CreatingProcessId,
          Params->Info.ProcessCrt.CreatingThreadId,
          Params->Info.ProcessCrt.FileOpenNameAvailable,
          Params->Strings[0].StrPtr);
                                                                                                                                                        
        if(Params->Info.ProcessCrt.FileOpenNameAvailable && Params->StrCnt)AddNewProcessToStack(Params->Info.ProcessCrt.ProcessId, Params->Strings[0].StrPtr, (Params->Strings[0].Length/2)-1);
		return 0;
	case CBProcess::evProcessTermination:
		return 0;
	case CBProcess::evProcessHndlCrt:
	case CBProcess::evProcessHndlDup:
	case CBProcess::evThreadHndlCrt:
	case CBProcess::evThreadHndlDup:
        DBGMSG("HandleOper %u: ProcessId=%08X, ThreadId=%08X, OriginatorProcessId=%08X, OriginatorThreadId=%08X, SourceProcessId=%08X, TargetProcessId=%08X, DesiredAccess=%08X, OriginalDesiredAccess=%08X",Params->Operation,
        Params->Info.HandleOper.ProcessId,
        Params->Info.HandleOper.ThreadId,
        Params->Info.HandleOper.OriginatorProcessId,
        Params->Info.HandleOper.OriginatorThreadId,
        Params->Info.HandleOper.SourceProcessId,
        Params->Info.HandleOper.TargetProcessId,
        Params->Info.HandleOper.DesiredAccess,
        Params->Info.HandleOper.OriginalDesiredAccess);

        Params->Info.ReturnAccess = Params->Info.HandleOper.DesiredAccess;  // ((PDWORD)Params)[2] = ((PDWORD)Params)[8];
		return 0;
	case CBProcess::evThreadCreation:
		return 0;
	case CBProcess::evThreadTermination:
		return 0;
 }
 return 1;    // No such operation
}
//====================================================================================
BOOL __stdcall ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
 static DWORD dwCheckPoint    = 1;
 static SERVICE_STATUS SvcStatus;
 SvcStatus.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
 SvcStatus.dwWaitHint         = dwWaitHint;
 if(dwCurrentState != (DWORD)-1)SvcStatus.dwCurrentState  = dwCurrentState;
 SvcStatus.dwWin32ExitCode    = dwWin32ExitCode;
 SvcStatus.dwCheckPoint       = ((dwCurrentState != SERVICE_RUNNING)&&(dwCurrentState != SERVICE_STOPPED))?(dwCheckPoint++):(0);
 SvcStatus.dwControlsAccepted = (dwCurrentState  != SERVICE_START_PENDING)?(SERVICE_ACCEPT_STOP):(0);  // Only STOP handler
 return SetServiceStatus(hSvcStatus, &SvcStatus);
}
//------------------------------------------------------------------------------------------------------------
VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode)        // This handler is called from main thread
{
 DBGMSG("CtrlCode: %08X",CtrlCode);
 if(SERVICE_CONTROL_STOP == CtrlCode)
  {
   ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
   DoAppFinalization();
   ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
  }
   else ReportSvcStatus(-1, NO_ERROR, 0);
 DBGMSG("Done");
}
//------------------------------------------------------------------------------------------------------------
VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
 DBGMSG("Enter");
 hSvcStatus = RegisterServiceCtrlHandlerA(SERVICE_NAME, ServiceCtrlHandler);
 if(!hSvcStatus){DBGMSG("RegisterServiceCtrlHandler failed!"); return;}
 ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 4000);                                 
 if(DoAppInitialization())ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
   else ReportSvcStatus(SERVICE_STOPPED, ERROR_APP_INIT_FAILURE, 0);
 DBGMSG("Done"); 
}
//------------------------------------------------------------------------------------------------------------
bool _stdcall IsAnotherInstRunning(void)      // TODO: A stealthy way to detect if another instance is running
{
 wchar_t NameBuf[128];
 wsprintfW(NameBuf, L"Global\\%ls", &MtxName);
 HANDLE hMut = CreateMutexW(NULL,FALSE,NameBuf);
 int LastErr = GetLastError();
 DBGMSG("Mutex: %08X, %u, %ls",hMut,LastErr,&NameBuf);
 if(!hMut)return (ERROR_ACCESS_DENIED == LastErr);    
 return (ERROR_ALREADY_EXISTS == LastErr);
}
//============================================================================================================
#ifdef _DEBUG
void _stdcall TestInjectionx(bool TgtX64)
{
 static bool DoOnce = true;
 wchar_t DDevPath[MAX_PATH];
 wchar_t ProcPath[MAX_PATH];             
 if(DoOnce){DoOnce=false; InitNtDllsHooks();}

 DBGMSG("TgtX64=%u",(int)TgtX64);
 STARTUPINFOW        PrStartInfo;
 PROCESS_INFORMATION ProcInf;
 memset(&PrStartInfo,0,sizeof(STARTUPINFO));
 PrStartInfo.cb          = sizeof(STARTUPINFO);
 PrStartInfo.dwFlags     = 0; 
 PrStartInfo.wShowWindow = SW_SHOWNORMAL;
 PVOID OldVal = 0;
 ProcPath[0] = StartUpDir[0];
 ProcPath[1] = ':';
 ProcPath[2] = 0;                                     
 QueryDosDeviceW(ProcPath,DDevPath,countof(DDevPath));    // Gives '\Device\HarddiskVolume1'
 int PathLen = wsprintfW(ProcPath,L"\\\\?%ls%lsTestProcess%u.exe",&DDevPath[7],&StartUpDir[2],(TgtX64?64:32));
 BOOL res = CreateProcessW(NULL,ProcPath,NULL,NULL,true,NORMAL_PRIORITY_CLASS|CREATE_SUSPENDED,NULL,NULL,&PrStartInfo,&ProcInf);    // Accepts only '\\?\'
 if(!res){DBGMSG("CreateProcess failed: %ls",ProcPath); return;}           
 SInjProcDesc obj;
 obj.InjType = InjectType;
 obj.Assign(ProcInf.hProcess, ProcInf.hThread, ProcPath, PathLen);
 TryInjectProcess(&obj);  
 ResumeThread(ProcInf.hThread);
  //      Sleep(3000);
 //TerminateProcess(GetCurrentProcess(),0);
}
#endif
//============================================================================================================
void _stdcall SysMain(DWORD UnkArg)
{
#ifndef _DEBUG
 static_assert(sizeof(void*) == 4, "Should not be compiled for x64!");
#endif
 SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);	 // Crash silently an error happens
 hInstance = GetModuleHandleA(NULL);
 GetModuleFileNameW(hInstance,StartUpDir,countof(StartUpDir)); 
 lstrcpyW(LogFilePath, StartUpDir);    
 TrimFilePath(StartUpDir);    
 lstrcpyW(GetFileExt(LogFilePath),L"log");

 SetConsoleCtrlHandler(ConHandlerRoutine, TRUE); 
 IsWow64Process(GetCurrentProcess(), &IsRunOnWow64);
 LoadConfiguration();
 DBGMSG("Starting Global Injector(%08X)...",GetCurrentThreadId());
 if(SetProcessPrivilegeState(true, SE_DEBUG_NAME, GetCurrentProcess()) < 0){DBGMSG("Failed to enable SeDebugPrivilege!");}
 if(SetProcessPrivilegeState(true, SE_CREATE_GLOBAL_NAME, GetCurrentProcess()) < 0){DBGMSG("Failed to enable SeCreateGlobalPrivilege!");}    // For sharing a mutex with a service 
                                
// GenerateBinLdr();    // <<<<<<<<<<<<<<<< Generate Loader array (Build with /Ox and /Ob2)
// GenerateBinDrv();    // <<<<<<<<<<<<<<<< No driver binaries in github repository!
#ifdef TESTRUN
 {
    DoAppInitialization();                  
    TestInjectionx(true);
    TestInjectionx(false);
      Sleep(3000);
    ExitProcess(0); 
 }
#endif
  
 OUTMSG("Global Injector v1.0");
 OUTMSG("");
 DBGMSG("Startup directory: %ls", &StartUpDir);
               
 PWSTR CmdLine = GetCommandLineW();
 DBGMSG("CmdLine: %ls",CmdLine);
 CmdLine = GetCmdLineParam(CmdLine, PWSTR(0));   // Skip EXE file name and path
 int ParCnt = -1;
 wchar_t Cmd[64];
 wchar_t Arg[MAX_PATH];
 while(*CmdLine)
  {
   DBGMSG("Parsing Arg: %ls",CmdLine);
   CmdLine = GetCmdLineParam(CmdLine, Cmd);
   if(NSTR::IsStrEqualIC("-I", Cmd))
    {
     CSrvControl srv;
     wchar_t ExePathBuf[MAX_PATH];
     ParCnt++;
     GetModuleFileNameW(hInstance,ExePathBuf,countof(ExePathBuf));
     DBGMSG("Service EXE: %ls",&ExePathBuf);                 
     if(int err = srv.CreateSrv(ExePathBuf, SrvName, SrvDesc, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, false)){LOGMSG("Install: CreateService failed with %u!", err); break;}
     if(int err = srv.StartSrv()){OUTMSG("StartService failed with %u!", err); break;}
     OUTMSG("The Service '%ls' has been created and started.",&SrvName);   
     break;
    } 
   if(NSTR::IsStrEqualIC("-U", Cmd))
    {
     CSrvControl srv;
     wchar_t ExePathBuf[MAX_PATH];
     ParCnt++;
     GetModuleFileNameW(hInstance,ExePathBuf,countof(ExePathBuf));
     DBGMSG("Service EXE: %ls",&ExePathBuf);
     if(int err = srv.CreateSrv(ExePathBuf, SrvName, NULL, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, true)){LOGMSG("Uninstall: OpenService failed with %u!", err); break;}
     if(int err = srv.StopSrv()){OUTMSG("StopService failed with %u!", err); break;}
     if(int err = srv.RemoveService()){OUTMSG("RemoveService failed with %u!", err);}   
     OUTMSG("The Service '%ls' has been stopped and removed.",&SrvName);  
     break;
    } 
  }

 if(ParCnt < 0)    // Show parameters and continue 
  {
   OUTMSG("");
   OUTMSG("-I: Install as a service");
   OUTMSG("-U: Uninstall the service");
   OUTMSG("");   
  }
  else     // Done with service control
   {
    DBGMSG("Done");
    ExitProcess(1);     
   }

 if(IsAnotherInstRunning()){OUTMSG("Another instance is already running!"); ExitProcess(-1);}  // TODO: Chech if already running as a service      

 SERVICE_TABLE_ENTRY ServiceTable[] = 
  {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION) ServiceMain},
        {NULL, NULL}
  };

 if(!StartServiceCtrlDispatcherA(ServiceTable))
  {
   DBGMSG("Not run as a service!");
   if(DoAppInitialization())
    {
     OUTMSG("Waiting...");
     WaitForSingleObject(hEvtCloseA, INFINITE);   //   pro.WaitForWorkerThread(INFINITE); 
    }
   DoAppFinalization();
   if(hEvtCloseB)SetEvent(hEvtCloseB); 
  }
 DBGMSG("Done");
 ExitProcess(0);  
}
//============================================================================================================                  
int _stdcall InitNtDllsHooks(void)
{
 PVOID pKiIntSystemCall  = NULL;   // Windows 7 x32 or below
 PVOID pKiFastSystemCall = NULL;   // Windows 7 x32 or below
 NtDllInfo.NtDllBase32 = (UINT64)GetModuleHandleA("ntdll.dll");
 if(IsRunOnWow64)NtDllInfo.NtDllBase64 = SWOW64Ext::getNTDLL64();                    
 DBGMSG("NtDll32Base=%p, NtDll64Base=%08X%08X",(PVOID)NtDllInfo.NtDllBase32,(DWORD)(NtDllInfo.NtDllBase64 >> 32), (DWORD)NtDllInfo.NtDllBase64);     
 if(!NtDllInfo.NtDllBase32 && !NtDllInfo.NtDllBase64)return -1;

 if(NtDllInfo.NtDllBase64)
  {
   DOS_HEADER DosHdr;
   WIN_HEADER<PETYPE64> WinHdr;
   SWOW64Ext::memcpy((UINT64)&DosHdr, NtDllInfo.NtDllBase64, sizeof(DosHdr));
   SWOW64Ext::memcpy((UINT64)&WinHdr, NtDllInfo.NtDllBase64+DosHdr.OffsetHeaderPE, sizeof(WinHdr));
   NtDllInfo.NtDllSize64 = WinHdr.OptionalHeader.SizeOfImage;
   UINT64 Addr = SWOW64Ext::GetProcAddress64(NtDllInfo.NtDllBase64, "LdrInitializeThunk");
   NtDllInfo.OffsLdrInitializeThunk64 = Addr - NtDllInfo.NtDllBase64;
   HDE64 dhde;
   BYTE TmpBuf[sizeof(NtDllInfo.OrigLdrInitializeThunk64)];
   SWOW64Ext::memcpy((DWORD64)&TmpBuf, Addr, sizeof(TmpBuf));
   for(UINT Offs=0;Offs < sizeof(TmpBuf);Offs += dhde.len)  
    {
     dhde.Disasm(&TmpBuf[Offs]);
     if((TmpBuf[Offs] == 0xE8)&&(dhde.len == 5))    // call rel  // LdrpInitialize
      {
       NtDllInfo.OffsLdrInitializeThunk64 = Addr - NtDllInfo.NtDllBase64;   
       NtDllInfo.OffsLdrpInitialize64 = RelAddrToAddr<UINT64>(Addr+Offs, 5, *(long*)&TmpBuf[Offs+1]) - NtDllInfo.NtDllBase64;
       NtDllInfo.OffsLdrpInitRet64    = (Addr + Offs + 5) - NtDllInfo.NtDllBase64;
       NtDllInfo.OffsLdrpInitPatch64  = NtDllInfo.OffsLdrpInitRet64 - 5;
       memcpy(&NtDllInfo.OrigLdrInitializeThunk64, &TmpBuf, sizeof(NtDllInfo.OrigLdrInitializeThunk64));
       DBGMSG("LdrInitializeThunk64=%08X%08X, LdrpInitialize64=%08X%08X", (DWORD)((NtDllInfo.NtDllBase64+NtDllInfo.OffsLdrInitializeThunk64) >> 32), (DWORD)(NtDllInfo.NtDllBase64+NtDllInfo.OffsLdrInitializeThunk64), (DWORD)((NtDllInfo.NtDllBase64+NtDllInfo.OffsLdrpInitialize64) >> 32), (DWORD)(NtDllInfo.NtDllBase64+NtDllInfo.OffsLdrpInitialize64));
       break;
      }
    }
  }

 if(NtDllInfo.NtDllBase32)
  {   
   DOS_HEADER* DosHdr           = (DOS_HEADER*)NtDllInfo.NtDllBase32;
   WIN_HEADER<PETYPE32>* WinHdr = (WIN_HEADER<PETYPE32>*)&((PBYTE)NtDllInfo.NtDllBase32)[DosHdr->OffsetHeaderPE];
   NtDllInfo.NtDllSize32 = WinHdr->OptionalHeader.SizeOfImage;
   if(!IsRunOnWow64)
    {
     pKiIntSystemCall  = GetProcAddress((HMODULE)NtDllInfo.NtDllBase32, "KiIntSystemCall");
     pKiFastSystemCall = GetProcAddress((HMODULE)NtDllInfo.NtDllBase32, "KiFastSystemCall");
    }
   UINT64 Addr = (UINT64)GetProcAddress((HMODULE)NtDllInfo.NtDllBase32, "LdrInitializeThunk");
   NtDllInfo.OffsLdrInitializeThunk32 = Addr - NtDllInfo.NtDllBase32;
   HDE32 dhde;
   BYTE TmpBuf[sizeof(NtDllInfo.OrigLdrInitializeThunk32)];
   memcpy(&TmpBuf, (PVOID)Addr, sizeof(TmpBuf));
   for(UINT Offs=0,PushCtr=0;Offs < sizeof(TmpBuf);Offs += dhde.len)   
    {
     dhde.Disasm(&TmpBuf[Offs]);
     if(TmpBuf[Offs] == 0xFF)PushCtr++;    // FF75 0C  push dword ptr ss:[ebp+C] 
     if((TmpBuf[Offs] == 0xE8)&&(dhde.len == 5))    // call rel // LdrpInitialize
      {
       if(PushCtr >= 2)NtDllInfo.IsX32LdrInitStdcall = true;
       NtDllInfo.OffsLdrInitializeThunk32 = Addr - NtDllInfo.NtDllBase32;   
       NtDllInfo.OffsLdrpInitialize32 = RelAddrToAddr<DWORD>(Addr+Offs, 5, *(long*)&TmpBuf[Offs+1]) - (DWORD)NtDllInfo.NtDllBase32;
       NtDllInfo.OffsLdrpInitRet32    = (Addr + Offs + 5) - NtDllInfo.NtDllBase32;
       NtDllInfo.OffsLdrpInitPatch32  = NtDllInfo.OffsLdrpInitRet32 - 5;
       memcpy(&NtDllInfo.OrigLdrInitializeThunk32, &TmpBuf, sizeof(NtDllInfo.OrigLdrInitializeThunk32));
       DBGMSG("LdrInitializeThunk32=%p, LdrpInitialize32=%p", (DWORD)(NtDllInfo.NtDllBase32+NtDllInfo.OffsLdrInitializeThunk32), (DWORD)(NtDllInfo.NtDllBase32+NtDllInfo.OffsLdrpInitialize32));
       break;
      }
    }
  } 

 if(IsRunOnWow64)
  {
   UINT64 AddrMap     = SWOW64Ext::GetProcAddress64(NtDllInfo.NtDllBase64, "NtMapViewOfSection");
   UINT64 AddrUnMap   = SWOW64Ext::GetProcAddress64(NtDllInfo.NtDllBase64, "NtUnmapViewOfSection");
   UINT64 AddrInitBlk = SWOW64Ext::GetProcAddress64(NtDllInfo.NtDllBase64, "LdrSystemDllInitBlock");    // Not for Windows 7
   SWOW64Ext::memcpy((UINT64)&NtDllInfo.CodeNtMapViewOfSection, AddrMap, sizeof(NtDllInfo.CodeNtMapViewOfSection));
   SWOW64Ext::memcpy((UINT64)&NtDllInfo.CodeNtUnmapViewOfSection, AddrUnMap, sizeof(NtDllInfo.CodeNtUnmapViewOfSection));
   if(AddrInitBlk)SWOW64Ext::memcpy((UINT64)&NtDllInfo.LdrSystemDllInitBlock, AddrInitBlk, sizeof(NtDllInfo.LdrSystemDllInitBlock));
   NtDllInfo.AddrOfLdrSystemDllInitBlock = AddrInitBlk;
  }
   else
    {
     PVOID AddrMap     = GetProcAddress((HMODULE)NtDllInfo.NtDllBase32, "NtMapViewOfSection");
     PVOID AddrUnMap   = GetProcAddress((HMODULE)NtDllInfo.NtDllBase32, "NtUnmapViewOfSection");
     PVOID AddrInitBlk = GetProcAddress((HMODULE)NtDllInfo.NtDllBase32, "LdrSystemDllInitBlock");
     memcpy(&NtDllInfo.CodeNtMapViewOfSection, AddrMap, sizeof(NtDllInfo.CodeNtMapViewOfSection));
     memcpy(&NtDllInfo.CodeNtUnmapViewOfSection, AddrUnMap, sizeof(NtDllInfo.CodeNtUnmapViewOfSection));
     if(pKiIntSystemCall && pKiFastSystemCall)
      {
       BYTE Patch[] = {0x8D,0x54,0x24,0x04,0xCD,0x2E,0x90};    // lea edx, [esp+4]; int 0x2E; nop      // 'int 0x2E' as from KiIntSystemCall does not return to KiFastSystemCallRet which will happen to be in unmapped memory of ntdll.dll
       memcpy(&NtDllInfo.CodeNtMapViewOfSection[5], &Patch, sizeof(Patch));    // First is mov EAX, ProcIdx
       memcpy(&NtDllInfo.CodeNtUnmapViewOfSection[5], &Patch, sizeof(Patch));  // First is mov EAX, ProcIdx
       DBGMSG("Created a fix for x32 Windows 7 KiFastSystemCall");
      }
     if(AddrInitBlk)memcpy(&NtDllInfo.LdrSystemDllInitBlock, AddrInitBlk, sizeof(NtDllInfo.LdrSystemDllInitBlock));
     NtDllInfo.AddrOfLdrSystemDllInitBlock = (UINT64)AddrInitBlk;
    }
 return 0;
}
//------------------------------------------------------------------------------------------------------------
bool _stdcall DeleteDriverFile(void)
{      
 if(!*DrvPath)return true;
 Wow64EnableWow64FsRedirection(FALSE);  // In case the driver has been saved to 'system32\drivers\' directory
 BOOL err = DeleteFileW(DrvPath);
 Wow64EnableWow64FsRedirection(TRUE);  
 if(err){DBGMSG("Removed the driver file: %ls",&DrvPath);}
   else {DBGMSG("Failed to delete the driver file(%u): %ls",GetLastError(), &DrvPath);}
 return err; 
}
//------------------------------------------------------------------------------------------------------------
bool _stdcall DoAppFinalization(void)
{
 DBGMSG("Finalizing...");
 int ErrCtr = 0;
 if(pro && drv)
  {
   if(pro->Remove() < 0){DBGMSG("Failed to remove Process filter!"); ErrCtr++;}
   if(drv->UnLoadDriver() < 0){DBGMSG("Failed to remove Callback driver!"); ErrCtr++;}
   delete(pro);
   delete(drv);
  }
 DBGMSG("Waiting for WorkerThread termination...");
 if(hEvtProcStack)SetEvent(hEvtProcStack); 
 if(hWorkerTh)WaitForSingleObject(hWorkerTh, 9000);
 if(ProcStack)delete(ProcStack);
 if(hEvtProcStack)CloseHandle(hEvtProcStack);
 DBGMSG("Deleting the driver file...");
 DeleteDriverFile();
 DBGMSG("Done");
 return (ErrCtr <= 0);
}
//------------------------------------------------------------------------------------------------------------
int _stdcall LoadCallbacDriver(PWSTR DrvName, PWSTR DrvNameEx, PWSTR DPath)
{
 bool DrvSha256 = (GetRealVersionInfo() & 0xFF) > 8;     // Windows 8
   
 int ResA = SaveDriverToFile(DrvName, IsRunOnWow64, DPath, DrvPath, DrvSha256);    
 if((ResA < 0) || !*DPath){DBGMSG("No driver file: %u!",ResA); return -1;}
 pro = new CBProcess();       // Tese two will be freed by DoAppFinalization
 drv = new CDrvLoader();      // todo: drv name must not match srv name
 if(drv->Initialize(DrvNameEx, DPath) < 0){DBGMSG("Driver loader init failed: %ls - %ls",DrvNameEx,DPath); DeleteDriverFile(); return -2;}
 int res = drv->LoadDriver();
 if(res < 0)
  {
   if((DWORD)res == 0xC0000428)   // Signature verification failed
    {
     DBGMSG("Trying a second driver: DrvSha256=%u",(int)DrvSha256);
     DeleteDriverFile(); 
     int ResA = SaveDriverToFile(DrvName, IsRunOnWow64, DPath, DrvPath, !DrvSha256);    
     if((ResA < 0) || !*DPath){DBGMSG("No second driver file: %u!",ResA); return -1;}
     if(drv->Initialize(DrvNameEx, DPath) < 0){DBGMSG("Driver loader init failed: %ls - %ls",DrvNameEx,DPath); DeleteDriverFile(); return -2;}
     res = drv->LoadDriver();
    }
   if(res < 0){DBGMSG("Failed to load the driver: %ls - %ls",DrvNameEx,DPath);DeleteDriverFile(); return -3;}
  }
 DeleteDriverFile();
 return 0;
}
//------------------------------------------------------------------------------------------------------------
bool _stdcall DoAppInitialization(void)
{                  
 DBGMSG("Initializing...");
 if(InitNtDllsHooks() < 0)return false;
 ProcStack = new CObjStack<SInjProcDesc>();
 DWORD ThreadID;
 if(ReceiveDbgLog)
  {
   wchar_t PipeName[MAX_PATH];
   wsprintfW(PipeName,L"\\\\.\\pipe\\DP%ls",&PipeNam);                                                
   hHostLogPipe = CreateNamedPipeW(PipeName,PIPE_ACCESS_INBOUND|FILE_FLAG_OVERLAPPED,PIPE_WAIT|PIPE_TYPE_BYTE,1,2048,2048,30000,NULL);   // PIPE_UNLIMITED_INSTANCES         PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE
   if(INVALID_HANDLE_VALUE != hHostLogPipe)
    {
     hDbgLogPipe = CreateFileW(PipeName,GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
     if(INVALID_HANDLE_VALUE == hDbgLogPipe){DBGMSG("Failed to open pipe: %ls",&PipeName); CloseHandle(hHostLogPipe); hHostLogPipe = NULL; ReceiveDbgLog = false;}
    }
     else {DBGMSG("Failed to create pipe: %ls",&PipeName); ReceiveDbgLog = false;}
  }
 hEvtProcStack = CreateEventW(NULL, FALSE, FALSE, NULL);
 hEvtCloseA = CreateEventW(NULL, TRUE,  FALSE, NULL);
 hWorkerTh = CreateThread(0, 0, WorkerThreadProc, NULL, 0, &ThreadID);   // Always required in case od a debugged target process
#ifndef TESTRUN
 wchar_t DrvNameEx[128]  = {0};
 wchar_t DPath[MAX_PATH] = {0};
 lstrcpyW(DrvNameEx, DrvName);    
 lstrcatW(DrvNameEx, L"Drv");      // The Driver service name must not be same as the loader service name

 if(LoadCallbacDriver(DrvName, DrvNameEx, DPath) < 0){DBGMSG("Failed to load the driver!"); return false;}                                            
 pro->Callback = UcbCallback;
 if(pro->Create(DrvNameEx) < 0){DBGMSG("Failed to connect to callback driver: %ls - %ls",&DrvNameEx,&DPath); return false;}

 DWORD FlgMask = CBProcess::emProcessCreationEvent;
// if(PROTSLFMSK || PROTTGTMSK)FlgMask |= CBProcess::emProcessHandleOperationEvent;    // This causes too many notifications from the driver
 if(pro->Start(FlgMask, DrvTimeout, DrvAltitude) < 0){DBGMSG("Failed to start event listening: %ls - %ls",&DrvNameEx,&DPath); return false;}    
 if(pro->IncludeProcessById(-1, true) < 0){DBGMSG("Failed to filter event listening: %ls - %ls",&DrvNameEx,&DPath); return false;}
#endif
 DBGMSG("Done");
 return true;
}
//------------------------------------------------------------------------------------------------------------ 
void _stdcall LoadConfiguration(void)
{
 wchar_t IniFilePath[MAX_PATH];  
 lstrcpyW(IniFilePath,LogFilePath);                                                          
 lstrcpyW(GetFileExt((PWSTR)&IniFilePath),L"ini");
 LogMode = INIRefreshValueInt<PWSTR>(CFGSECNAME,L"LogMode",LogMode|lmCons,(PWSTR)&IniFilePath);     // LogMode   = lmCons|lmFile;// lmFile;  //lmCons;
 NormDllPaths = INIRefreshValueInt<PWSTR>(CFGSECNAME,L"NormDllPaths",NormDllPaths,(PWSTR)&IniFilePath);
 ForceTgtCon = INIRefreshValueInt<PWSTR>(CFGSECNAME,L"ForceTgtCon",ForceTgtCon,(PWSTR)&IniFilePath); 
 ReceiveDbgLog = INIRefreshValueInt<PWSTR>(CFGSECNAME,L"ReceiveDbgLog",ReceiveDbgLog,(PWSTR)&IniFilePath);            
 UseMainThread = INIRefreshValueInt<PWSTR>(CFGSECNAME,L"UseMainThread",UseMainThread,(PWSTR)&IniFilePath);  
 DeepExeName = INIRefreshValueInt<PWSTR>(CFGSECNAME,L"DeepExeName",DeepExeName,(PWSTR)&IniFilePath);
 DirectInject = INIRefreshValueInt<PWSTR>(CFGSECNAME,L"DirectInject",DirectInject,(PWSTR)&IniFilePath);
 InjectType = INIRefreshValueInt<PWSTR>(CFGSECNAME,L"InjectType",InjectType,(PWSTR)&IniFilePath);             
 DrvTimeout = INIRefreshValueInt<PWSTR>(CFGSECNAME,L"DrvTimeout",DrvTimeout,(PWSTR)&IniFilePath);
 DrvAltitude = INIRefreshValueInt<PWSTR>(CFGSECNAME,L"DrvAltitude",DrvAltitude,(PWSTR)&IniFilePath);
 INIRefreshValueStr<PWSTR>(CFGSECNAME, L"DrvName", L"", DrvName, countof(DrvName), (PWSTR)&IniFilePath);
 INIRefreshValueStr<PWSTR>(CFGSECNAME, L"SrvName", L"", SrvName, countof(SrvName), (PWSTR)&IniFilePath);  
 INIRefreshValueStr<PWSTR>(CFGSECNAME, L"MtxName", L"", MtxName, countof(MtxName), (PWSTR)&IniFilePath);     
 INIRefreshValueStr<PWSTR>(CFGSECNAME, L"SrvDesc", ctENCSW(L"Local Security Mitigation Service"), SrvDesc, countof(SrvDesc), (PWSTR)&IniFilePath);  
                                                       
 for(int ctr=0,tot=sizeof(ModExts)/sizeof(SNameExtCfg);ctr < tot;ctr++)
   if(ModExts[ctr].Name)ModExts[ctr].ValLen = INIRefreshValueStr<PWSTR>(NAMSECNAME, ModExts[ctr].Name, ModExts[ctr].Value, ModExts[ctr].Value, countof(ModExts[ctr].Value), (PWSTR)&IniFilePath); 
 for(int ctr=0,tot=sizeof(DirExts)/sizeof(SNameExtCfg);ctr < tot;ctr++)
   if(DirExts[ctr].Name)DirExts[ctr].ValLen = INIRefreshValueStr<PWSTR>(NAMSECNAME, DirExts[ctr].Name, DirExts[ctr].Value, DirExts[ctr].Value, countof(DirExts[ctr].Value), (PWSTR)&IniFilePath); 
            
 if(GDirPathLen = INIRefreshValueStr<PWSTR>(NAMSECNAME, L"DirGlobal", L"DllGlobal", GlobalDllDir, countof(GlobalDllDir), (PWSTR)&IniFilePath))    // Should not be created automatically 
  {
   if(GlobalDllDir[1] != ':')
    {
     wchar_t TmpDir[MAX_PATH];   
     PWSTR SrcPtr = TmpDir;
     if(IsFilePathDelim(*SrcPtr))SrcPtr++;
     if(IsFilePathDelim(SrcPtr[GDirPathLen-1]))SrcPtr[GDirPathLen-1] = 0;
     lstrcpyW(TmpDir, GlobalDllDir);
     lstrcpyW(GlobalDllDir,StartUpDir);
     lstrcatW(GlobalDllDir, SrcPtr);      
    }       
     else if(IsFilePathDelim(GlobalDllDir[GDirPathLen-1]))GlobalDllDir[GDirPathLen-1]=0;   // Must not end with a slash

   wchar_t DrPath[4] = {GlobalDllDir[0],':',0}; 
   wchar_t DDevPath[MAX_PATH];
   if(DWORD PLen = QueryDosDeviceW(DrPath,DDevPath,countof(DDevPath)))  // Returns number of stored char, not actual length of the string
    {
     lstrcatW(DDevPath, &GlobalDllDir[2]);   // 'X:\Path' to '\Dev ice\HarddiskVolume1\Path'
     DDevPath[4] = '\\';    
     DDevPath[5] = DDevPath[6] = '?';
     lstrcpyW(GlobalDllDir, &DDevPath[4]);
     GDirPathLen = lstrlenW(GlobalDllDir);
    }
   DBGMSG("Global DLL directory: %ls", &GlobalDllDir);
  }

 if(!*DrvName)
  {
   lstrcpyW(DrvName,GetFileName((PWSTR)&IniFilePath));
   GetFileExt((PWSTR)&DrvName)[-1] = 0;
  }
 if(!*SrvName)
  {
   lstrcpyW(SrvName,GetFileName((PWSTR)&IniFilePath));
   GetFileExt((PWSTR)&SrvName)[-1] = 0;
  }
 if(!*MtxName)
  {
   lstrcpyW(MtxName,GetFileName((PWSTR)&IniFilePath));
   GetFileExt((PWSTR)&MtxName)[-1] = 0;
  }
 lstrcpyW(PipeNam,GetFileName((PWSTR)&IniFilePath));
 GetFileExt((PWSTR)&PipeNam)[-1] = 0;     
 BuildNameExts();
}
//------------------------------------------------------------------------------------------------------------

