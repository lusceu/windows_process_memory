#include "windows.h"
#include "securitybaseapi.h"
#include "processthreadsapi.h"
#include "stdio.h"
#include "psapi.h"
#include "tlhelp32.h"

// ntquerysysteminformation -> peb 
// peb -> image base address -> pe header
// pe header -> section headers


//  https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-privilege 
//  SetPrivilege enables/disables process token privilege.
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    LUID luid;
    BOOL bRet=FALSE;

    if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        TOKEN_PRIVILEGES tp;

        tp.PrivilegeCount=1;
        tp.Privileges[0].Luid=luid;
        tp.Privileges[0].Attributes=(bEnablePrivilege) ? SE_PRIVILEGE_ENABLED: 0;
        //
        //  Enable the privilege or disable all privileges.
        //
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
        {
            //
            //  Check to see if you have proper access.
            //  You may get "ERROR_NOT_ALL_ASSIGNED".
            //
            bRet=(GetLastError() == ERROR_SUCCESS);
        }
    }
    return bRet;
}


#define PROC_ID 0x654
#define PROC_INFORMATION_CLASS 0
// pinvoke.net structure shows 48 bytes 
#define PROC_INFORMATION_LENGTH 48

typedef struct _THREAD_BASIC_INFORMATION {
  NTSTATUS            ExitStatus;
  PVOID               TebBaseAddress;
  PVOID               ClientId;
  PVOID               AffinityMask;
  PVOID               Priority;
  PVOID               BasePriority;
} THREAD_BASIC_INFORMATION;


typedef struct _PEB {
  UCHAR InheritedAddressSpace;
  UCHAR ReadImageFileExecOptions;
  UCHAR BeingDebugged;
  UCHAR BitField;
  ULONG ImageUsesLargePages: 1;
  ULONG IsProtectedProcess: 1;
  ULONG IsLegacyProcess: 1;
  ULONG IsImageDynamicallyRelocated: 1;
  ULONG SpareBits: 4;
  PVOID Mutant;
  PVOID ImageBaseAddress;
  PVOID Ldr;
  PVOID ProcessParameters;
  PVOID Reserved4[3];
  PVOID AtlThunkSListPtr;
  PVOID Reserved5;
  ULONG Reserved6;
  PVOID Reserved7;
  ULONG Reserved8;
  ULONG AtlThunkSListPtr32;
  PVOID Reserved9[45];
  BYTE  Reserved10[96];
  PVOID PostProcessInitRoutine;
  BYTE  Reserved11[128];
  PVOID Reserved12[1];
  ULONG SessionId;
} PEB, *PPEB;

typedef struct _TEB {
  PVOID Reserved1[12];
  PPEB  ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} TEB, *PTEB;

int main()
{

	// get debug privileges for current process
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken;

	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
	    SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
	    CloseHandle(hToken);
	    printf("Got Debug privileges. \n");
	}	

	
	// gets process snapshot and enumerates threads for target process id
	HANDLE tlhlp_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, PROC_ID);	
	if(tlhlp_handle == INVALID_HANDLE_VALUE) 
		printf("Error in CreateToolhelp32Snapshot: %d \n", GetLastError() ); 

	
	THREADENTRY32 *pthread_entry = malloc(sizeof(THREADENTRY32));
	pthread_entry->dwSize = sizeof(THREADENTRY32);
	BOOL res = Thread32First(tlhlp_handle, pthread_entry);	
	if(!res){
		printf("Thread32First failed: %d\n", GetLastError());
	}

	// search process's threads to get a thread id -> used further to get thread handle
	DWORD thread_id;
	while(res){
		if( pthread_entry->th32OwnerProcessID == PROC_ID ){
			thread_id = pthread_entry->th32ThreadID;
			printf("Found matching Thread ID: %x \n", thread_id);
			break;
		}
		res = Thread32Next(tlhlp_handle, pthread_entry);	
	}

	// get a thread handle -> used further in ntquerythreadinformation
	HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
	if(thread_handle == INVALID_HANDLE_VALUE)
		printf("OpenThread failed \n");
		printf("ThreadHandle:  %x\n", thread_handle);

	
	NTSTATUS (*ntquerythread)(HANDLE, DWORD, PVOID, ULONG, PULONG);
	HMODULE hMod = LoadLibraryA("ntdll.dll");
	if(hMod != NULL){
		printf("LoadLibrary successfull\n");
		ntquerythread = GetProcAddress(hMod, "NtQueryInformationThread");	
		if(ntquerythread != NULL){
			printf("NtQueryInformationThread found\n");
		}
	}

	THREAD_BASIC_INFORMATION *tbi = malloc(sizeof(THREAD_BASIC_INFORMATION));
	ULONG return_size;
	NTSTATUS nt_res = ntquerythread(thread_handle, 0, tbi, sizeof(THREAD_BASIC_INFORMATION), &return_size);
	printf("NtQueryInformationThread result: %d \n", nt_res);	
	printf("TEB address: %x \n", tbi->TebBaseAddress);	

	// try to read teb 
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PROC_ID);		
	printf("Process handle: %x \n", hProcess);	

	TEB *pteb = malloc(sizeof(TEB));
	BOOL read_res = ReadProcessMemory(hProcess, tbi->TebBaseAddress, pteb, sizeof(TEB), &return_size);
	//BOOL read_res = ReadProcessMemory(hProcess, 0x000000C10F91C000, pteb, sizeof(TEB), &return_size);
	printf("Read result: %d \n", read_res);
	printf("Peb address: %x \n", pteb->ProcessEnvironmentBlock);
	PEB *ppeb = malloc(sizeof(PEB));
	read_res = ReadProcessMemory(hProcess, pteb->ProcessEnvironmentBlock, ppeb, sizeof(PEB), &return_size);
	printf("ImageBase address: %x \n", ppeb->ImageBaseAddress);


	// final loop
	while(1){
		Sleep(1);	
	}

	

}

