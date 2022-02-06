#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <Windows.h>

#define SIZEOF(x) sizeof(x)/sizeof(x[0])


UCHAR *g_buff;


int search_section(PIMAGE_NT_HEADERS nt, DWORD addr)
{
    PIMAGE_OPTIONAL_HEADER32 opt     = (PIMAGE_OPTIONAL_HEADER32)&(nt->OptionalHeader);
    PIMAGE_SECTION_HEADER    section = (PIMAGE_SECTION_HEADER)(nt + 1);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        DWORD size = (section->Misc.VirtualSize + opt->SectionAlignment - 1) /
                      opt->SectionAlignment * opt->SectionAlignment;

        if (addr >= section->VirtualAddress &&
            addr <= (section->VirtualAddress + size - 1))
        {
            return i;
        }

        section++;
    }

    return -1;
}

void update_reloc_block(UCHAR *buff,
                        PIMAGE_SECTION_HEADER section,
                        PIMAGE_BASE_RELOCATION block,
                        DWORD fa, int section_id)
{
    // 相对于节数据开始位置
    DWORD offset = block->VirtualAddress - section->VirtualAddress;

    // 数据数量
    DWORD count = (block->SizeOfBlock - 8) / 2;

    // 数据位置
    fa += sizeof(IMAGE_BASE_RELOCATION);
    WORD *data = (WORD*)(buff + fa);

    for (UINT j = 0; j < count; j++)
    {
        WORD addr = (*data) & 0x0fff;

        DWORD value = *(DWORD*)(buff + section->PointerToRawData + offset + addr);

        if (value >= 0x40d1cc && value <= 0x40d334)
        {
            DWORD *p = (DWORD*)(g_buff + section->PointerToRawData + offset + addr);
            *p = value + 4;
        }

        data++;
    }
}

void update_reloc_table(UCHAR *buff)
{
    PIMAGE_DOS_HEADER        dos          = (PIMAGE_DOS_HEADER)buff;
    PIMAGE_NT_HEADERS        nt           = (PIMAGE_NT_HEADERS)(buff + dos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER32 opt          = (PIMAGE_OPTIONAL_HEADER32)&(nt->OptionalHeader);
    PIMAGE_SECTION_HEADER    section_list = (PIMAGE_SECTION_HEADER)(nt + 1);
    PIMAGE_SECTION_HEADER    section;
    PIMAGE_BASE_RELOCATION   block;

    DWORD fa;   // 文件位置
    DWORD va = opt->DataDirectory[5].VirtualAddress;

    if (0 == va)
    {
        return; // 没有重定位表
    }

    // 查找重定位表所在节
    int section_id = search_section(nt, va);

    if (section_id < 0)
    {
        return; // 没有重定位表
    }

    section = &section_list[section_id];

    fa = section->PointerToRawData + opt->DataDirectory[5].VirtualAddress - section->VirtualAddress;

    va -= fa;   // 相对位置

    for (int i = 0; ; i++)
    {
        block = (PIMAGE_BASE_RELOCATION)(buff + fa);

        if (0 == block->VirtualAddress || 0 == block->SizeOfBlock)
        {
            break;
        }

        // 查找重定位表数据块所在的节
        section_id = search_section(nt, block->VirtualAddress);

        if (section_id < 0)
        {
            printf("search section %08x error", block->VirtualAddress);
            return; // 出错
        }

        update_reloc_block(buff, &section_list[section_id], block, fa, section_id);

        fa += block->SizeOfBlock;
    }
}

void update_import_thunk(UCHAR *buff,
                         PIMAGE_SECTION_HEADER section,
                         DWORD thunk_list_addr,
                         char *lib)
{
    DWORD fa = section->PointerToRawData + thunk_list_addr - section->VirtualAddress;
    PIMAGE_THUNK_DATA32 thunk = (PIMAGE_THUNK_DATA32)(buff + fa);

    DWORD type;
    DWORD value;

    while (thunk->u1.Function != 0)
    {
        type = thunk->u1.Function >> 31;
        value = thunk->u1.Function & 0xEFFFFFFF;

        if (0 == type) // 按名称导入
        {
            if (0 == strcmp(lib, "ADVAPI32.dll") ||
                0 == strcmp(lib, "DownloadSDK.dll") ||
                0 == strcmp(lib, "KERNEL32.dll"))
            {

                DWORD *t = (DWORD*)(g_buff + fa);
                *t = value + 4; // 数据加4
            }
            else
            {
                DWORD *t = (DWORD*)(g_buff + fa + 4); // 地址加4
                *t = value + 4; // 数据加4
            }
        }

        thunk++;
        fa += sizeof(IMAGE_THUNK_DATA32);
    }
}

void update_import_library(UCHAR *buff,
                           PIMAGE_SECTION_HEADER section,
                           PIMAGE_IMPORT_DESCRIPTOR import,
                           DWORD fa)
{
    int fa_name = section->PointerToRawData + import->Name - section->VirtualAddress;
    char *lib_name = (char*)(buff + fa_name);

    // 因为数据已经移动,所以所有的库名称都要修改
    *(DWORD*)(g_buff + fa + 12) = import->Name + 4;

    // 其它库的Thunk指针需要修改
    if (0 != strcmp(lib_name, "ADVAPI32.dll") &&
        0 != strcmp(lib_name, "DownloadSDK.dll") &&
        0 != strcmp(lib_name, "KERNEL32.dll"))
    {
        *(DWORD*)(g_buff + fa) = import->OriginalFirstThunk + 4;
        *(DWORD*)(g_buff + fa + 16) = import->FirstThunk + 4;
    }

    // 因为数据已经移动,所以所有Thunk数据都要修改
    update_import_thunk(buff, section, import->FirstThunk, lib_name);
    update_import_thunk(buff, section, import->OriginalFirstThunk, lib_name);
}

void update_import_table(UCHAR *buff)
{
    PIMAGE_DOS_HEADER        dos     = (PIMAGE_DOS_HEADER)buff;
    PIMAGE_NT_HEADERS        nt      = (PIMAGE_NT_HEADERS)(buff + dos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER32 opt     = (PIMAGE_OPTIONAL_HEADER32)&(nt->OptionalHeader);
    PIMAGE_SECTION_HEADER    section = (PIMAGE_SECTION_HEADER)(nt + 1);
    PIMAGE_IMPORT_DESCRIPTOR import;

    // 查找导入表数据所在节
    int section_id = search_section(nt, opt->DataDirectory[1].VirtualAddress);

    if (section_id < 0)
    {
        return;
    }

    section = &section[section_id];

    // 导入表在文件中的位置
    DWORD fa = section->PointerToRawData + opt->DataDirectory[1].VirtualAddress - section->VirtualAddress;

    import = (PIMAGE_IMPORT_DESCRIPTOR)(buff + fa);

    while (import->OriginalFirstThunk != 0)
    {
        update_import_library(buff, section, import, fa);
        fa += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        import++;
    }
}

int main(int argc,char **argv)
{
    char name[512];
    strcpy_s(name, sizeof(name), argv[0]);

    char *file = strrchr(name, '\\');
    strcpy_s(file + 1, 100, "DownloadSDKServerOrg.exe");

    FILE *fp = NULL;
    fopen_s(&fp, name, "rb");

    if (NULL == fp)
    {
        printf("open %s error %d", name, GetLastError());
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    UINT size = ftell(fp);
    UCHAR *buff = malloc(size);
    fseek(fp, 0, SEEK_SET);
    fread(buff, 1, size, fp);
    fclose(fp);

    if (buff[0] != 'M' || buff[1] != 'Z')
    {
        printf("%s is not pe file", name);
        return -2;
    }

    g_buff = malloc(size);
    memcpy(g_buff, buff, size);

    // 移动数据, first thunk 向下移动4字节, 为指向LoadLibraryA移出空间
    memcpy(g_buff + 0x0c5cc, buff + 0x0c5c8, 0x0c738 - 0x0c5c8);

    // 移动数据, Origi thunk 向下移动4字节, 为指向LoadLibraryA移出空间
    memcpy(g_buff + 0x10184, buff + 0x10180, 0x117a3 - 0x10180);

    // 移动数据, reloc       向下移动2字节, 为调用LoadLibraryA移出空间
    memcpy(g_buff + 0x21f06, buff + 0x21f04, 0x22620 - 0x21f04);

    // 增加数据, thunk所指向的数据, 序号0x03d7,名称LoadLibraryA
    strcpy_s((char*)(g_buff + 0x117a7), 100, "\xd7\x03LoadLibraryA");

    // 增加数据, first thunk 新移出的地址4字节, 指向LoadLibraryA, 117a7+d000-c400=123A7
    *((DWORD*)(g_buff + 0x0c5c8)) = 0x123a7;

    // 增加数据, Origi thunk 新移出的地址4字节, 指向LoadLibraryA, 117a7+d000-c400=123A7
    *((DWORD*)(g_buff + 0x10180)) = 0x123a7;

    // 修改数据, 重定位目录中定义的重定位大小0x1220, 增加2个字节
    *((DWORD*)(g_buff + 0x19c)) = 0x1222;

    // 修改数据, 重定位数据块大小0x138, 增加4个字节
    *((WORD*)(g_buff + 0x21dd0)) = 0x13a;

    // 修改数据, reloc 新移出的地址2字节, 地址指向0x41cf52
    *((WORD*)(g_buff + 0x21f04)) = 0x3f52;      // call [0x41cf52] 调用LoadLibraryA

    // 修改数据, 跳到0x40CF44
    *((DWORD*)(g_buff + 0xAcb1)) = 0x168f;      // call 0x40CF44

    // 新增代码 
    UCHAR data[] = {
        'x',  't',  '.',  'd', 'l', 'l', 0x00,  // "D:\2.code\4.nmake.example\tmp\xt.dll"
        0x60,                                   // pushad
        0x9c,                                   // pushfd
        0xe8, 0x00, 0x00, 0x00, 0x00,           // call 下一条地址
        0x5e,                                   // pop esi
        0x83, 0xee, 0x0e,                       // sub esi,0xc
        0x56,                                   // push esi
        0xff, 0x15, 0xc8, 0xd1, 0x40, 0x00,     // call LoadLibraryA("xt.dll")
        //0x05, 0x40, 0x10, 0x00, 0x00,           // add eax,0x1040
        //0x8b, 0xcc,                             // mov ecx,esp
        //0x83, 0xc1, 0x2c,                       // add ecx,0x2c
        //0x8b, 0x31,                             // mov esi,[ecx]
        //0x56,                                   // push esi
        //0xff, 0xd0,                             // call eax
        //0x5e,                                   // pop esi 平栈
        0x9d,                                   // popfd
        0x61,                                   // popad
        0xe9, 0xdb, 0xed, 0xff, 0xff            // jmp 0040BD38
    };

    memcpy(g_buff + 0xc33d, data, sizeof(data)); // va=0x40CF44
    
    // 更新导入表数据
    update_import_table(buff);
    
    // 更新重定向表数据
    update_reloc_table(buff);

    // 写文件
    strcpy_s(name, 100, "DownloadSDKServer.exe");
    fopen_s(&fp, name, "wb+");

    if (NULL == fp)
    {
        printf("create %s error %d", name, GetLastError());
        return -3;
    }

    fwrite(g_buff, 1, size, fp);
    fclose(fp);

    printf("create %s crack ok", name);
    return 0;
}