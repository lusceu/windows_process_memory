#include "windows.h"
#include "securitybaseapi.h"
#include "processthreadsapi.h"

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

int main()
{

	//printf("Hello World");
	//return 0;

	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken;

	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
	    SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
	    CloseHandle(hToken);
	}	

	while(1){
		
	}

}

