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

BYTE __NewCode[7] = { 0xE9, 0x0, 0x0, 0x0, 0x0, 0x0 };
BYTE __OldCode[7] = { 0 };

int fun2();
int fun1();
void InlineHook();


void InlineHook()
{

    if (ReadProcessMemory(INVALID_HANDLE_VALUE, fun2, __OldCode, 7, NULL) == 0)
    {
        printf("ReadProcessMemory error\n");
        return;
    }

    DWORD JmpAddress = (DWORD)fun1;
    // 计算自定义函数的地址.
    // 构造新头部代码
    __NewCode[0] = 0xB8;            //
    memcpy(&__NewCode[1], &JmpAddress, 4);    // mov eax, _JmpAddr
    __NewCode[5] = 0xFF;            //
    __NewCode[6] = 0xE0;            // jmp eax
    DWORD dwOldProtect = 0;
    //DWORD dwOldProtect = 0; //旧保护属性
    // 去内存保护
    ::VirtualProtect(fun2, 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    //写入跳转，开始Hook
    WriteProcessMemory(INVALID_HANDLE_VALUE, fun2, __NewCode, 7, NULL);
    // 写内存保护
    ::VirtualProtect(fun2, 7, dwOldProtect, &dwOldProtect);
}




int main()
{
    InlineHook();
    fun2();
}

int fun2() {
    puts("Right!");
    return 0;
}

int fun1() {
    puts("If You see me,That's Mean's you are success!");
    return 0;
}

