
<p align="center">                 
  <h1 align="center">GInjer</h1>
</p>  
 
<img align="left" hspace="20" src="/Main.png">

+ *A signed kernel driver is used to receive a process creation callbacks*
+ *A normal or reflective injection is supported*
+ *Injection of selected DLLs into almost every newly created processes*
+ *Injection of a DLL before **and** after static import initialization*
+ *Injection of an x64 DLL during WOW64 initialization*
+ *Ability to inject before a process initialization*
+ *No APC injection or remote thread creation is used*
+ *No VirtualAllocEx\\NtAllocateVirtualMemory or VirtualProtectEx\\NtProtectVirtualMemory is used*
+ *No any of target Process` threads handle is opened*
+ *No PROCESS_VM_READ or PROCESS_VM_WRITE rights are required for the target process` handle*     
---
# Command Line
Install as a service: -I

Uninstall the service: -U

# Load Configuration

**Defined in INI file**

ProcessName.[Before|After][x32|x64]

DirectoryName.[Before|After][x32|x64]

Examples: TestProcess32.exe.ad; TestProcess64.exe.bq; TEST.bd; TEST.aq

Or a separate directory to load DLLs with any names.

# DLL Configuration

**Stored in PE Header::MajorImageVersion**

 0x0002 - Reflective loading
 
 0x0004 - Load only from the same directory where a process` EXE started
 
 0x0008 - Allows loading of the x64 DLL into a WOW64 process
 
 0x0010 - Load before a process initialization (Reflective only)

# Search Path Example

C:\\TEST\\GINJER\\TestProcess32.exe.bd

C:\\TEST\\GINJER\\TestProcess32.exe.bq

C:\\TEST\\GINJER\\TestProcess32.exe.ad

C:\\TEST\\GINJER\\TestProcess32.exe.aq

C:\\TEST\\GINJER\\GINJER.bd

C:\\TEST\\GINJER\\GINJER.bq

C:\\TEST\\GINJER\\GINJER.ad

C:\\TEST\\GINJER\\GINJER.aq

C:\\TEST\\GINJER\\!ldrl\\

C:\\TEST\\GINJER\\!ldrg\\

C:\\TEST\\TEST.bd

C:\\TEST\\TEST.bq

C:\\TEST\\TEST.ad

C:\\TEST\\TEST.aq

C:\\TEST\\!ldrg\\

C:\\TEST\\GINJER\\DllGlobal\\


                                               
