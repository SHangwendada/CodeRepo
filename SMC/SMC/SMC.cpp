#include <windows.h>
#include<stdio.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>
#include <string.h>

#pragma code_seg(".hello")
int fun()
{
	puts("Hello");
	return 0;
}
#pragma code_seg()
#pragma comment(linker, "/SECTION:.hello,ERW")

void Fun1end()
{
}

void xxor(char* soure, int dLen, int key)   //异或
{
	for (int i = 0; i < dLen; i++)
	{
		soure[i] = soure[i] ^ key;
	}
}
void SMC(char* pBuf, int key)     //SMC解密/加密函数
{
	const char* szSecName = ".hello";
	short nSec;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_SECTION_HEADER pSec;
	pDosHeader = (PIMAGE_DOS_HEADER)pBuf;
	pNtHeader = (PIMAGE_NT_HEADERS)&pBuf[pDosHeader->e_lfanew];
	nSec = pNtHeader->FileHeader.NumberOfSections;
	pSec = (PIMAGE_SECTION_HEADER)&pBuf[sizeof(IMAGE_NT_HEADERS) + pDosHeader->e_lfanew];
	for (int i = 0; i < nSec; i++)
	{
		if (strcmp((char*)&pSec->Name, szSecName) == 0)
		{
			int pack_size;
			char* packStart;
			pack_size = pSec->SizeOfRawData;
			packStart = &pBuf[pSec->VirtualAddress];
			xxor(packStart, pack_size, key);
			return;
		}
		pSec++;
	}
}
void UnPack()   //解密/加密函数
{
	char* hMod;
	hMod = (char*)GetModuleHandle(0);  //获得当前的exe模块地址
	SMC(hMod, 0xff);
}




int main(void)
{

	UnPack();
	UnPack();//编译时请注释一个
	fun();
	return 0;
}