#include "windows.h"
#include "stdio.h"
#include "memoryapi.h"

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


#define PROC_ID 0x1698
#define PROC_INFORMATION_CLASS 0
// pinvoke.net structure shows 48 bytes 
#define PROC_INFORMATION_LENGTH 48
#define _WIN64 1

// https://docs.microsoft.com/en-us/windows/desktop/api/winternl/nf-winternl-ntqueryinformationprocess
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    ULONG_PTR PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

// https://www.nirsoft.net/kernel_struct/vista/PEB.html
typedef struct _PEB
{
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
     ULONG Ldr;
     ULONG ProcessParameters;
     PVOID SubSystemData;
     PVOID ProcessHeap;
     PRTL_CRITICAL_SECTION FastPebLock;
     PVOID AtlThunkSListPtr;
     PVOID IFEOKey;
     ULONG CrossProcessFlags;
     ULONG ProcessInJob: 1;
     ULONG ProcessInitializing: 1;
     ULONG ReservedBits0: 30;
     union
     {
          PVOID KernelCallbackTable;
          PVOID UserSharedInfoPtr;
     };
     ULONG SystemReserved[1];
     ULONG SpareUlong;
     ULONG FreeList;
     ULONG TlsExpansionCounter;
     PVOID TlsBitmap;
     ULONG TlsBitmapBits[2];
     PVOID ReadOnlySharedMemoryBase;
     PVOID HotpatchInformation;
     VOID * * ReadOnlyStaticServerData;
     PVOID AnsiCodePageData;
     PVOID OemCodePageData;
     PVOID UnicodeCaseTableData;
     ULONG NumberOfProcessors;
     ULONG NtGlobalFlag;
     LARGE_INTEGER CriticalSectionTimeout;
     ULONG HeapSegmentReserve;
     ULONG HeapSegmentCommit;
     ULONG HeapDeCommitTotalFreeThreshold;
     ULONG HeapDeCommitFreeBlockThreshold;
     ULONG NumberOfHeaps;
     ULONG MaximumNumberOfHeaps;
     VOID * * ProcessHeaps;
     PVOID GdiSharedHandleTable;
     PVOID ProcessStarterHelper;
     ULONG GdiDCAttributeList;
     PRTL_CRITICAL_SECTION LoaderLock;
     ULONG OSMajorVersion;
     ULONG OSMinorVersion;
     WORD OSBuildNumber;
     WORD OSCSDVersion;
     ULONG OSPlatformId;
     ULONG ImageSubsystem;
     ULONG ImageSubsystemMajorVersion;
     ULONG ImageSubsystemMinorVersion;
     ULONG ImageProcessAffinityMask;
     ULONG GdiHandleBuffer[34];
     PVOID PostProcessInitRoutine;
     PVOID TlsExpansionBitmap;
     ULONG TlsExpansionBitmapBits[32];
     ULONG SessionId;
     ULARGE_INTEGER AppCompatFlags;
     ULARGE_INTEGER AppCompatFlagsUser;
     PVOID pShimData;
     PVOID AppCompatInfo;
     ULONG CSDVersion;
     ULONG * ActivationContextData;
     ULONG * ProcessAssemblyStorageMap;
     ULONG * SystemDefaultActivationContextData;
     ULONG * SystemAssemblyStorageMap;
     ULONG MinimumStackCommit;
     ULONG * FlsCallback;
     LIST_ENTRY FlsListHead;
     PVOID FlsBitmap;
     ULONG FlsBitmapBits[4];
     ULONG FlsHighIndex;
     PVOID WerRegistrationData;
     PVOID WerShipAssertPtr;
} PEB, *PPEB;


int main()
{

	/*
		Obtaining Privileges and NtQueryInformationProcess function address
	*/ 

	PROCESS_BASIC_INFORMATION *PebBuffer = malloc(PROC_INFORMATION_LENGTH);
	PULONG InfoLength = 0;
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
	

	// call NtQueryInformationProcess to find the baseaddress of the PEB of the target process 
	// NtQueryInformationProcess needs dynamic linking
	HMODULE hMod = LoadLibraryA("ntdll.dll");
	if(hMod != NULL){
		printf("LoadLibrary successfull\n");
		ntqueryip = GetProcAddress(hMod, "NtQueryInformationProcess");	
		if(ntqueryip != NULL){
			printf("NtQueryInformationProcess found\n");
		}

	}



	/*
		Reading the PEB 

	*/ 	

	NTSTATUS ntstat = ntqueryip(hProcess, PROC_INFORMATION_CLASS, PebBuffer, PROC_INFORMATION_LENGTH, InfoLength);

	ULONG *PebBaseAddress = PebBuffer->PebBaseAddress;	
	printf("NtQueryInformationProcess status: %x \n", ntstat);
	printf("Bytes written: %d \n", InfoLength);
	printf("Address of PEB in target process: %#016x \n", PebBaseAddress); 

	/* iat hooking
	peb -> imagebaseaddress 
	peb.imagebaseaddress -> image_dos_header
	image_dos_header.e_lfanew -> image_nt_headers(coff+optional)	
		image_nt_headers.FileHeader.NumberOfSections -> anzahl sections
		image_nt_headers + sizeof(image_nt_headers) -> first section (image_section_header) 
			immediately followed by further sections 

	if image_section_header.Name == ".idata"
		image_section_header.VirtualAddress = IdataSectionAddress	
	
	IdataSectionAddress	
		0: ImportDirectoryTable -> First image_import_descriptor
		(contains directory entries for imported dlls, last entry contains 0)
		
		if(image_import_descriptor.Name == "target.dll")
			iat = image_import_descriptor.FirstThunk (image_thunk_data)	
	
		first_thunk.Function -> address of dll function
		first_thunk.AddressOfData -> image_import_by_name
		image_import_by_name.Name -> function name

			
	*/ 

	PPEB ProcessEnvironmentBlock = malloc(sizeof(PEB));	
	PVOID ImageBaseAddress;
	ULONG bytes_read = 0; 
	BOOL res = ReadProcessMemory(hProcess, PebBaseAddress, ProcessEnvironmentBlock, sizeof(PEB), &bytes_read);
	if(!res){
		printf("ReadProcessMemory failed reading PEB.\n");
	} else {
		ImageBaseAddress = ProcessEnvironmentBlock->ImageBaseAddress;	
		printf("ImageBaseAddress: %#016x \n", ImageBaseAddress);
	}
	

	/* 
		Reading IMAGE_DOS_HEADER and IMAGE_NT_HEADERS
		
	*/
	
	IMAGE_DOS_HEADER *DosHeader = malloc(sizeof(IMAGE_DOS_HEADER));
	IMAGE_NT_HEADERS *NtHeadersBaseAddress;
	res = ReadProcessMemory(hProcess, ImageBaseAddress, DosHeader, sizeof(IMAGE_DOS_HEADER), &bytes_read);
	if(!res){
		printf("ReadProcessMemory failed reading IMAGE_DOS_HEADER.\n");
	} else {
		NtHeadersBaseAddress = ImageBaseAddress + DosHeader->e_lfanew;	
		printf("Dos-Header->magic : %#010x \n", DosHeader->e_magic);
		printf("DOS-Header->e_lfanew: %#016x \n", NtHeadersBaseAddress);
	}

	IMAGE_NT_HEADERS *NtHeaders = malloc(sizeof(IMAGE_NT_HEADERS));	
	res = ReadProcessMemory(hProcess, NtHeadersBaseAddress, NtHeaders, sizeof(IMAGE_NT_HEADERS), &bytes_read);
	if(!res){
		printf("ReadProcessMemory failed reading IMAGE_NT_HEADERS.\n");
	} else {
		printf("NtHeaders->Signature: %#010x \n", NtHeaders->Signature);
	}
	
	IMAGE_FILE_HEADER FileHeader = NtHeaders->FileHeader;	
	printf("NtHeader->FileHeader->NumberOfSections: %#010x \n", FileHeader.NumberOfSections);
	

	/*
		Reading Sections
		
	*/

	// first section follows NtHeaders	

	IMAGE_OPTIONAL_HEADER OptionalHeader = NtHeaders->OptionalHeader;

	PVOID SectionHeaderBaseAddress = (PVOID) NtHeadersBaseAddress + sizeof(IMAGE_NT_HEADERS);
	printf("SizeOfHeaders: %#010x \n", sizeof(IMAGE_NT_HEADERS));
	printf("NtHeadersBaseAddress: %#010x \n", NtHeadersBaseAddress);
	printf("SectionHeaderBaseAddress: %#010x \n", SectionHeaderBaseAddress);
	IMAGE_SECTION_HEADER *SectionHeader = malloc(sizeof(IMAGE_SECTION_HEADER));	
	
	for(int i = 0; i < FileHeader.NumberOfSections; i++){

		printf("SectionHeaderBaseAddress: %#010x \n", SectionHeaderBaseAddress);
		res = ReadProcessMemory(hProcess, SectionHeaderBaseAddress, SectionHeader, sizeof(IMAGE_SECTION_HEADER), &bytes_read);
		if(!res){
			printf("ReadProcessMemory failed reading IMAGE_SECTION_HEADER.\n");
		} else {
			
			printf("SectionHeader->Name: %s \n", SectionHeader->Name);
			printf("SectionHeader->VirtualAddress: %#018x \n", SectionHeader->VirtualAddress);

		}

		SectionHeaderBaseAddress = (PVOID) SectionHeaderBaseAddress + sizeof(IMAGE_SECTION_HEADER);
	}

	// final loop
	while(1){
		Sleep(1);	
	}

	

}

