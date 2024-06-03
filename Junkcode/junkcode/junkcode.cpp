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

int main(){

    _asm {
        jz label1 // zf不为0 跳转
        jnz label1 // zf标志位 为0跳转
        _EMIT 0x89
        label1 :
    }
    _asm
    {
        call f1
        f1 :
        add     byte ptr[esp + 0], 6
        ret
        _EMIT 0x89
    }

    printf("hello");

}
