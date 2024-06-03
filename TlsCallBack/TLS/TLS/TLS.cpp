#include<iostream>
#include<algorithm>
#include<cstdio>
#include<cmath>
#include<map>
#include<vector>
#include<queue>
#include<stack>
#include<set>
#include<string>
#include<cstring>
#include<list>
#include<stdlib.h>
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <iostream>
#include <string.h>


using namespace std;
typedef VOID(*PFUNMSG)(LPCWSTR szMsg, LPCWSTR Title);
#pragma comment(linker,"/INCLUDE:__tls_used")
HMODULE hModule;
PFUNMSG Crypto;




VOID NTAPI tls_callback(
    PVOID DllHandle,
    DWORD Reason,
    PVOID Reserved
)
{
    printf("hello\n");
}


#pragma data_seg(".CRT$XLX")
PIMAGE_TLS_CALLBACK pTlsfun[] = { tls_callback ,0 };


int main() {


}
