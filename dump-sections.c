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


#define PROC_ID 0x117C 
#define PROC_INFORMATION_CLASS 0
// pinvoke.net structure shows 48 bytes 
#define PROC_INFORMATION_LENGTH 48

// https://docs.microsoft.com/en-us/windows/desktop/api/winternl/nf-winternl-ntqueryinformationprocess
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    ULONG_PTR PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

int main()
{

	PROCESS_BASIC_INFORMATION *peb_buffer = malloc(PROC_INFORMATION_LENGTH);
	PULONG info_length = 0;
	NTSTATUS (*ntqueryip)(HANDLE, int, PVOID, ULONG, PULONG);

	// get debug privileges for current process
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken;

	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
	    SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
	    CloseHandle(hToken);
	}	

	// get process handle for the target process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PROC_ID);
	if(hProcess != NULL){
		printf("Obtained process handle %d \n", hProcess);
	}
	
	// call NtQueryInformationProcess to find the basaddress of the PEB of the target process 
	// NtQueryInformationProcess needs dynamic linking
	HMODULE hMod = LoadLibraryA("ntdll.dll");
	if(hMod != NULL){
		printf("LoadLibrary successfull\n");
		ntqueryip = GetProcAddress(hMod, "NtQueryInformationProcess");	
		if(ntqueryip != NULL){
			printf("NtQueryInformationProcess found\n");
		}

	}

	
	// MISSING BASE ADDRESS	
	NTSTATUS ntstat = ntqueryip(hProcess, PROC_INFORMATION_CLASS, peb_buffer, PROC_INFORMATION_LENGTH, info_length);
	printf("NtQueryInformationProcess status: %x \n", ntstat);
	printf("Bytes written: %d \n", info_length);
	printf("Address of PEB in target process: %#016x \n", (*peb_buffer).PebBaseAddress); 
	
	// MISSING BASE ADDRESS
	// psapi - module information of a process - reads modules with adresses relative to base address
	HMODULE *module_array = malloc(256);
	int module_array_size;
	BOOL mod_res = K32EnumProcessModules(hProcess, module_array, 512, &module_array_size);
	printf("Module result: %d \n", mod_res);
	int module_entries = module_array_size / sizeof(HMODULE);
	printf("Module entries: %d \n", module_entries);
	for(int i = 0; i < module_entries; i += 1){
		printf("Module array entry: %#016x 	", module_array[i]);
		char* module_name[60];
		DWORD name_size = 60;
		K32GetModuleFileNameExA(hProcess, module_array[i], module_name, name_size); 
		printf("Module name: %s, %d \n", module_name, name_size); 
 	}	
		
	// in Anlehnung an https://guidedhacking.com/threads/get-module-base-address-tutorial-dwgetmodulebaseaddress.5781/
	// MISSING BASE ADDRESS
	// gets process snapshot and enumerates modules
	HANDLE tlhlp_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PROC_ID);	
	if(tlhlp_handle == INVALID_HANDLE_VALUE) 
		printf("Error in CreateToolhelp32Snapshot: %d \n", GetLastError() ); 


	MODULEENTRY32 modentry32;
	if(Module32First(tlhlp_handle, &modentry32))
		printf("Base-address of %s in target process: %#016x \n", modentry32.szModule, modentry32.modBaseAddr); 
	else
		printf("Error in Module32First: %d \n", GetLastError());

	while( Module32Next(tlhlp_handle, &modentry32) ){
		printf("Base-address of %s in target process: %#016x \n", modentry32.szModule, modentry32.modBaseAddr); 
	}
	
	
	while(1){
		Sleep(1);	
	}

}

