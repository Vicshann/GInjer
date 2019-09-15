
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

#define WIN32_LEAN_AND_MEAN             

#include <windows.h>


//------------------------------------------------------------------------------------------------------------
class CBProcess
{
#pragma pack( push, 1 )
public:
static const DWORD DefTimeout     = 0;     // No timeout
static const DWORD DefAltitude    = 0x00061AB7;
static const DWORD WrkThRdyWait   = 9000;      // Was INFINITE
static const DWORD TermEvtTimeout = 9000;  // Was INFINITE

struct SUStr      // Size 0x10
{
 DWORD  Unknown;
 DWORD  Length;   // In bytes
 union
  {
   PWSTR  StrPtr;
   UINT64 Pointer;
  };
};

union UPRInfo      // Size 0x20
{
 BYTE  DataBlk[0x20];
 DWORD ReturnAccess;
 struct {
    DWORD ProcessId;
    DWORD ThreadId;            // NULL for Process events
    DWORD OriginatorProcessId;
    DWORD OriginatorThreadId;
    DWORD SourceProcessId;     // Valid for Duplication only
    DWORD TargetProcessId;     // Valid for Duplication only
    DWORD DesiredAccess;       // Return this unmodified to allow the same access
    DWORD OriginalDesiredAccess;
  } HandleOper;            

 struct {                  // Need: MainThreadId(Should be accessible to the driver but missing here for some reason) and CurrentDirectory
    DWORD ProcessId;
    DWORD ParentProcessId;
    DWORD CreatingProcessId;
    DWORD CreatingThreadId;
    DWORD FileOpenNameAvailable;
    // Str 0: ProcessName         // '\Device\HarddiskVolume1\Windows\System32\calc.exe'
    // Str 1: ImageFileName
    // Str 2: CommandLine
  } ProcessCrt;

 struct {
    DWORD ProcessId;
    // Str 0: ProcessName
  } ProcessTrm;

 struct {
    DWORD ProcessId;
    DWORD ThreadId;
    DWORD CreatingProcessId;
    DWORD CreatingThreadId;
  } ThreadCrt;

 struct {
    DWORD ProcessId;
    DWORD ThreadId;
  } ThreadTrm;
};

struct UCB_REQUEST_PARAMETERS    // SEventNtfy, size 0x88
{      
 DWORD   Operation;      // WORD?  EEvent   // 3 and 5 is for handle duplication
 DWORD   StrCnt;       
 UPRInfo Info;
 SUStr   Strings[6];     // Size 0x60          
 };
private:
struct SReqCtx98
{
/*00*/ DWORD  CbkResult;   // 0
/*04*/ DWORD  BufSize;     // SystemInfo.dwPageSize;
/*08*/ UINT64 Buffer;      // malloc    // Shared buffer
/*10*/ UCB_REQUEST_PARAMETERS Params;
};

struct SCtx2220BC   // Size is 0x1C + length od RegKey
{
/*00*/ DWORD Version;  // Should be 0
/*04*/ DWORD Unused;   // Unused
/*08*/ DWORD Timeout;  // In Ms
/*0C*/ DWORD CbkMask; 
/*10*/ DWORD Altitude;      // 400000 <> 409999  // Default: 400055
/*14*/ DWORD StrictAltitude;  // BOOL
/*18*/ DWORD RegKeyLen;    // Let it be a constant 0?
/*1C*/ char  RegKey[0];    // Unused1    
};

struct SCtx2220A8
{
/*00*/ DWORD Timeout;     // In Ms
/*04*/ DWORD CbkMask;
/*08*/ DWORD RegKeyLen;   // Let it be a constant 16?
/*0C*/ char  RegKey[0];   // Unused1
};

struct PROCESS_NAME_DATA 
{
 WORD  ExcludeList; 
 WORD  IncludeChildren; 
 DWORD NameLen; 
 WCHAR Name[MAX_PATH];    // What about a really nong paths? // Allocate this struct dynamically?
};

struct PROCESS_ID_DATA 
{
 WORD  ExcludeList; 
 WORD  IncludeChildren; 
 DWORD ProcessId;
};
#pragma pack( pop )

public:
enum EEvent {evProcessCreation=0,evProcessTermination,evProcessHndlCrt,evProcessHndlDup,evThreadHndlCrt,evThreadHndlDup,evThreadCreation,evThreadTermination};
enum ECEvtMsk {emProcessCreationEvent=0x01,emProcessTerminationEvent=0x02,emProcessHandleOperationEvent=0x04,emThreadHandleOperationEvent=0x08,emThreadCreationEvent=0x10,emThreadTerminationEvent=0x20};  // See ObRegisterCallbacks: PsProcessType; PsThreadType

private:
 HANDLE hDevDispatch;
 HANDLE hKernelWorker;
 HANDLE hFilterHandle;    
 HANDLE hDevUcb;
 HANDLE hWorkerTh;    
 HANDLE hWrkThRdEvt;
 SReqCtx98 ReqCtx;
 wchar_t DrvSrvName[MAX_PATH];

//------------------------------------------------------------------------------------------------------------
HANDLE GetUcbDeviceHandle(void)     // OK
{
 HANDLE hDev = NULL;
 DWORD  BytesReturned = 0;
 if(!DeviceIoControl(this->hKernelWorker, 0x222000, 0, 0, &hDev, sizeof(HANDLE), &BytesReturned, NULL) || (BytesReturned != sizeof(HANDLE)))return NULL;   // <<<<<< this->hFilterHandle
 return hDev;
}
//------------------------------------------------------------------------------------------------------------
BOOL SetWorkerThreadsNumber(DWORD ThNum)   // OK
{
 DWORD  BytesReturned = 0;
 return DeviceIoControl(this->hKernelWorker, 0x222018, &ThNum, sizeof(DWORD), 0, 0, &BytesReturned, NULL);   // <<<<<<<<<<<<<<<<<< Was hFilterHandle
}
//------------------------------------------------------------------------------------------------------------
BOOL GetUcbRequest(SReqCtx98* InOutReq)   // OK
{
 DWORD  BytesReturned = 0;
 return DeviceIoControl(this->hDevUcb, 0x222007, InOutReq, sizeof(SReqCtx98), 0, 0, &BytesReturned, NULL); 
}
//------------------------------------------------------------------------------------------------------------
BOOL StartFilter(void)    // OK
{
 DWORD  BytesReturned = 0;
 return DeviceIoControl(this->hFilterHandle, 0x2220B4, 0, 0, 0, 0, (LPDWORD)&BytesReturned, NULL);    
}
//------------------------------------------------------------------------------------------------------------
BOOL StopFilter(void)    // OK
{
 DWORD  BytesReturned = 0;
 return DeviceIoControl(this->hFilterHandle, 0x2220B8, 0, 0, 0, 0, (LPDWORD)&BytesReturned, NULL);  
}
//------------------------------------------------------------------------------------------------------------
BOOL AddFilteredProcessById(UINT ProcessId, int ExcludeList, int IncludeChildren)     // OK
{
 DWORD  BytesReturned = 0;
 PROCESS_ID_DATA Ctx = {ExcludeList, IncludeChildren, ProcessId};
 return DeviceIoControl(this->hFilterHandle, 0x2220D0, &Ctx, sizeof(Ctx), 0, 0, &BytesReturned, NULL);    
}
//------------------------------------------------------------------------------------------------------------
BOOL AddFilteredProcessByName(wchar_t* ProcessName, int ExcludeList, int IncludeChildren)   // OK
{
 DWORD  BytesReturned = 0;
 int NameLen = lstrlenW(ProcessName) * 2;
 PROCESS_NAME_DATA Ctx = {ExcludeList, IncludeChildren, NameLen};     // it is not allowed to send PROCESS_NAME_DATA with unused chars at end
 lstrcpynW(Ctx.Name, ProcessName, MAX_PATH);
 return DeviceIoControl(this->hFilterHandle, 0x2220D4, &Ctx, (sizeof(Ctx)-(MAX_PATH * sizeof(WCHAR)))+Ctx.NameLen, 0, 0, &BytesReturned, NULL);    
}
//------------------------------------------------------------------------------------------------------------
BOOL RemoveFilteredProcessById(UINT ProcessId, int ExcludeList)
{
 DWORD  BytesReturned = 0;
 PROCESS_ID_DATA Ctx = {ExcludeList, 0, ProcessId};
 return DeviceIoControl(this->hFilterHandle, 0x2220D8, &Ctx, sizeof(Ctx), 0, 0, &BytesReturned, 0);
}
//------------------------------------------------------------------------------------------------------------
BOOL RemoveFilteredProcessByName(wchar_t* ProcessName, int ExcludeList)
{
 DWORD  BytesReturned = 0;
 int NameLen = lstrlenW(ProcessName) * 2;
 PROCESS_NAME_DATA Ctx = {ExcludeList, 0, NameLen};
 lstrcpynW(Ctx.Name, ProcessName, MAX_PATH);
 return DeviceIoControl(this->hFilterHandle, 0x2220DC, &Ctx, sizeof(Ctx), 0, 0, &BytesReturned, NULL);    
}
//------------------------------------------------------------------------------------------------------------
BOOL UcbResetTimeout(UINT Timeout)     // ???
{
 DWORD  BytesReturned = 0;
 return DeviceIoControl(NULL, 0x222010, &Timeout, sizeof(UINT), 0, 0, &BytesReturned, NULL);   // DevHndl: Worker + 8 
}
//------------------------------------------------------------------------------------------------------------
HANDLE UcbGetTokenByTid(UINT Tid)   // ???
{
 DWORD  BytesReturned = 0;
 HANDLE ResHndl = NULL;
 if(DeviceIoControl(NULL, 0x222020, &Tid, sizeof(UINT), &ResHndl, sizeof(HANDLE), &BytesReturned, NULL))return ResHndl;   // Return is void* or DWORD?      // DevHndl: Worker + 8 
 DBGMSG("Failed!"); 
 return INVALID_HANDLE_VALUE;
}
//------------------------------------------------------------------------------------------------------------
HANDLE UcbGetOriginatorToken(void)   // ???
{
 DWORD  BytesReturned = 0;
 HANDLE ResHndl = NULL;
 if(DeviceIoControl(NULL, 0x22200C, 0, 0, &ResHndl, sizeof(HANDLE), &BytesReturned, NULL))return ResHndl;   // Return is void* or DWORD?  
 DBGMSG("Failed!"); 
 return INVALID_HANDLE_VALUE;
}
//------------------------------------------------------------------------------------------------------------
int UcbGetOriginatorThreadId(UINT* Tid)   // ???
{
 DWORD  BytesReturned = 0;
 return DeviceIoControl(NULL, 0x22201C, 0, 0, Tid, sizeof(UINT), &BytesReturned, NULL);
}
//------------------------------------------------------------------------------------------------------------
int UcbGetOriginatorProcessId(UINT* Pid)  // ???
{
 DWORD  BytesReturned = 0;
 return DeviceIoControl(NULL, 0x222014, 0, 0, Pid, sizeof(UINT), &BytesReturned, NULL);
}
//------------------------------------------------------------------------------------------------------------
int UcbGetOriginatorProcessName(wchar_t* Buffer, UINT BufferLength)   // ???
{
 DWORD  BytesReturned = 0;
 if(!DeviceIoControl(NULL, 0x222008, 0, 0, Buffer, BufferLength, &BytesReturned, NULL)){DBGMSG("Failed!"); return -1;}
 return BytesReturned;
}
//------------------------------------------------------------------------------------------------------------
int UcbGetProcessNameByPid(UINT Pid, wchar_t* Buffer, UINT BufferLength)   // ???
{
 DWORD BytesReturned = 0;
 if(!DeviceIoControl(NULL, 0x222024, &Pid, sizeof(UINT), Buffer, BufferLength, &BytesReturned, NULL)){DBGMSG("Failed!"); return -1;}
 return BytesReturned;
}
//------------------------------------------------------------------------------------------------------------
BOOL GetProcessName(DWORD ProcessId, wchar_t *NameBuf, UINT* NameBufLen)      // NameBufLen n bytes     // ???
{
 DWORD BytesReturned = 0;
 PROCESS_NAME_DATA PnRes;
 if(!DeviceIoControl(this->hDevDispatch, 0x2220F8u, &ProcessId, sizeof(DWORD), &PnRes, sizeof(PnRes), &BytesReturned, 0)){DBGMSG("Failed!"); return FALSE;}   // Can return 0 and GetLastError ERROR_MORE_DATA
 UINT Len = (PnRes.NameLen > *NameBufLen)?(*NameBufLen):(PnRes.NameLen);
 memcpy(NameBuf, &PnRes.Name, Len);
 *NameBufLen = Len;
 return TRUE;
}
//------------------------------------------------------------------------------------------------------------
UINT GetFilterId(void)      // OK           // ID is For  CBFSProcessComposeUcbTerminationEventName
{
 DWORD BytesReturned = 0;
 DWORD FilterId = 0;
 if(!DeviceIoControl(this->hFilterHandle, 0x2220B0, 0, 0, &FilterId, sizeof(DWORD), &BytesReturned, 0)){DBGMSG("Failed!"); return -1;}  
 return FilterId;
}
//------------------------------------------------------------------------------------------------------------
// "Global\\" + "%ServiceName%" + "UcbTerminationEvent" + FilterID as int     // L"Global\\cbfsprocess2017UcbTerminationEvent9" 
int RemoveFilter(void)
{
 wchar_t EvtPath[MAX_PATH];
 UINT FilterId = this->GetFilterId();  
 if(FilterId == (UINT)-1){DBGMSG("No filter ID!"); return -1;}  
 wsprintfW(EvtPath, L"Global\\%lsUcbTerminationEvent%u",this->GetServiceName(),FilterId);      // TODO: Encrypt this string
 CloseHandle(this->hFilterHandle);        // Breaks GetUcbRequest waiting
 HANDLE hTermEvt = OpenEventW(SYNCHRONIZE, FALSE, EvtPath);  // 0x100000
 if(!hTermEvt){DBGMSG("No termination event: %ls", &EvtPath); return 1;}     // Not an Error?
 DBGMSG("Waiting for termination event: %ls", &EvtPath);
 WaitForSingleObject(hTermEvt, TermEvtTimeout);
 CloseHandle(hTermEvt);
 this->hFilterHandle = NULL;
 DBGMSG("Done!"); 
 return 0;
}
//------------------------------------------------------------------------------------------------------------
// L"\\Device\\{066B0CB8-ADD8-4d50-ACE4-AFA10257284E}-%d"
bool OpenDispatcherDevice(void)
{
 wchar_t FileName[MAX_PATH+4];
 wsprintfW(FileName, L"\\\\.\\%ls",this->GetServiceName()); 
 DBGMSG("Path: %ls",&FileName);                 
 this->hDevDispatch = CreateFileW(FileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);    // 0xC0000000
 DBGMSG("hDevDispatch: %p, Err=%u",this->hDevDispatch, GetLastError());
 return (this->hDevDispatch && (this->hDevDispatch != INVALID_HANDLE_VALUE));
}
//------------------------------------------------------------------------------------------------------------
void CloseDispatcherDevice(void)
{
 if(this->hDevDispatch != INVALID_HANDLE_VALUE)CloseHandle(this->hDevDispatch);
 this->hDevDispatch = INVALID_HANDLE_VALUE;
}
//------------------------------------------------------------------------------------------------------------
BOOL DispatcherDeviceIoControl(DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, DWORD* aBytesReturned)
{
 DWORD BytesReturned = 0;
 BOOL  Res = DeviceIoControl(this->hDevDispatch, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, &BytesReturned, NULL);
 if(aBytesReturned)*aBytesReturned = BytesReturned;
 return Res;
}
//------------------------------------------------------------------------------------------------------------
int CreateFilter(UINT CbkMask, UINT Timeout=DefTimeout, UINT Altitude=DefAltitude)
{
 DWORD BytesReturned = 0;
 SCtx2220BC CtxNew;
 SCtx2220A8 CtxOld;

 CtxNew.CbkMask = CtxOld.CbkMask = CbkMask;   // 0x0F; 
 CtxNew.Timeout = CtxOld.Timeout = Timeout;
 CtxNew.RegKeyLen = CtxOld.RegKeyLen = 0;
 *CtxNew.RegKey = *CtxOld.RegKey = 0;

 CtxNew.Version  = 0;  // Must be 0
 CtxNew.Unused   = 0;  // ???
 CtxNew.Altitude = Altitude;  //400055;    // Default
 CtxNew.StrictAltitude = FALSE;

 this->hKernelWorker = NULL;
 if(!this->OpenDispatcherDevice())return -1;
 if(!this->DispatcherDeviceIoControl(0x2220BC, &CtxNew, sizeof(CtxNew), &this->hFilterHandle, sizeof(HANDLE), &BytesReturned))
  {
   DBGMSG("Trying Old!"); 
   if(!this->DispatcherDeviceIoControl(0x2220A8, &CtxOld, sizeof(CtxOld), &this->hFilterHandle, sizeof(HANDLE), &BytesReturned)){DBGMSG("Failed to get filter handle!"); this->CloseDispatcherDevice(); return -2;}
  }
 this->CloseDispatcherDevice();
 DBGMSG("hFilterHandle: %p",this->hFilterHandle);
// UcbCreateWorker(1, 1);
 if(!DeviceIoControl(this->hFilterHandle, 0x2220AC, 0, 0, &this->hKernelWorker, sizeof(HANDLE), &BytesReturned, NULL)){DBGMSG("Failed to get kernel worker!"); return -3;}   // Get KernelWorker handle
 DBGMSG("hKernelWorker: %p",this->hKernelWorker);
 if(!this->SetWorkerThreadsNumber(1)){DBGMSG("Failed to set worker threads!"); return -4;} 
// UcbStartWorker 
 this->hWrkThRdEvt = CreateEventW(NULL, TRUE, FALSE, NULL);
 this->hWorkerTh = CreateThread(0, 0, UcbWorkerThreadProc, this, 0, &BytesReturned);
 if(!this->hWorkerTh)return -5;
 WaitForSingleObject(this->hWrkThRdEvt, WrkThRdyWait);    
 CloseHandle(this->hWrkThRdEvt);
 DBGMSG("Done!");
 return 0;
}
//------------------------------------------------------------------------------------------------------------
static DWORD __stdcall UcbWorkerThreadProc(LPVOID lpThreadParameter)
{
 CBProcess* This = (CBProcess*)lpThreadParameter;
 This->hDevUcb = This->GetUcbDeviceHandle();    // Why here? // Driver remembers this thread?
 if(!This->hDevUcb){DBGMSG("Failed to get filter ucb Device Handle!"); return -1;}
 if(This->hWrkThRdEvt)SetEvent(This->hWrkThRdEvt);    // Report that we are ready   // Is this really required?????
 DBGMSG("Entering event loop.");
// DumpHexDataFmt((PBYTE)&This->ReqCtx, sizeof(SReqCtx98), 16); 
 while(This->GetUcbRequest(&This->ReqCtx))
  {
   DBGMSG("Event: %u", This->ReqCtx.Params.Operation); 
//   DumpHexDataFmt((PBYTE)&This->ReqCtx, sizeof(SReqCtx98), 16); 
   if(This->Callback)This->ReqCtx.CbkResult = This->Callback(&This->ReqCtx.Params);     // You can return ERROR_ACCESS_DENIED
     else This->ReqCtx.CbkResult = 0;    // 0=OK,1=NoSuchCallback,
  }
 DBGMSG("Finish: %u",GetLastError());
 CloseHandle(This->hKernelWorker);     // Must be done here! (And in this order?)   // Breaks UcbTerminationEvent ?
 CloseHandle(This->hWorkerTh);         // Must be done here! // Breaks WaitForWorkerThread
 CloseHandle(This->hDevUcb);           // Must be done here!                  // Or this breaks UcbTerminationEvent ?
 return 0;
}
//------------------------------------------------------------------------------------------------------------
wchar_t* GetServiceName(void)
{
 return this->DrvSrvName;
}
//------------------------------------------------------------------------------------------------------------

public:
int (_stdcall* Callback)(UCB_REQUEST_PARAMETERS* Params);

//------------------------------------------------------------------------------------------------------------
CBProcess(void)
{
 memset(this,0,sizeof(CBProcess));
 this->ReqCtx.BufSize = 0x1000; //SysInfo.dwPageSize;
 this->ReqCtx.Buffer  = (UINT64)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,this->ReqCtx.BufSize); 
}
//------------------------------------------------------------------------------------------------------------
~CBProcess()
{
 this->Remove();
 if(this->ReqCtx.Buffer)HeapFree(GetProcessHeap(),0,(PVOID)this->ReqCtx.Buffer);
}
//------------------------------------------------------------------------------------------------------------
bool WaitForWorkerThread(DWORD msTimeout)  // Returns TRUE if time out, you can loop as 'while(WaitForWorkerThread(1000))'
{
 return (WAIT_TIMEOUT == WaitForSingleObject(this->hWorkerTh, msTimeout));
}
//------------------------------------------------------------------------------------------------------------
int Create(wchar_t* SrvName)
{
 lstrcpynW(this->DrvSrvName,SrvName,sizeof(this->DrvSrvName));
 DBGMSG("Done!");
 return 0;
}
//------------------------------------------------------------------------------------------------------------
int Remove(void)   // Stop and unload the driver
{
 this->Stop();
 DBGMSG("Done!");
 return 0;
}
//------------------------------------------------------------------------------------------------------------
int Start(UINT CbkMask, UINT Timeout=DefTimeout, UINT Altitude=DefAltitude)
{
 DBGMSG("Timeout=%u, Altitude=%u",Timeout,Altitude);
 if(this->hFilterHandle)return 1;
 if(this->CreateFilter(CbkMask, Timeout, Altitude) < 0){DBGMSG("Failed to create filter!"); return -1;}
 if(!this->StartFilter()){DBGMSG("Failed to start filter!"); return -2;}
 DBGMSG("Done!");
 return 0;
}
//------------------------------------------------------------------------------------------------------------
int Stop(void)
{
 if(!this->hFilterHandle)return 1;
 DBGMSG("Stopping filter...");
 if(!this->StopFilter()){DBGMSG("Failed to stop filter!");}
 DBGMSG("Removing filter...");
 if(this->RemoveFilter() < 0){DBGMSG("Failed to remove filter!"); return -1;}
 DBGMSG("Done!");
 return 0;
}
//------------------------------------------------------------------------------------------------------------
int IncludeProcessById(UINT ProcessId, bool IncludeChildren){return -1 + this->AddFilteredProcessById(ProcessId, 0, IncludeChildren);} 
int IncludeProcessByName(wchar_t* ProcessName, bool IncludeChildren){return -1 + this->AddFilteredProcessByName(ProcessName, 0, IncludeChildren);}
//------------------------------------------------------------------------------------------------------------

};
//------------------------------------------------------------------------------------------------------------
