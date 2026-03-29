#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <TlHelp32.h>

DWORD find_minecraft ( ) {
    HANDLE snap = CreateToolhelp32Snapshot ( TH32CS_SNAPPROCESS , 0 );
    if ( snap == INVALID_HANDLE_VALUE ) return 0;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof ( pe );
    DWORD pid = 0;
    if ( Process32FirstW ( snap , &pe ) ) {
        do {
            if ( _wcsicmp ( pe.szExeFile , L"javaw.exe" ) == 0 || _wcsicmp ( pe.szExeFile , L"java.exe" ) == 0 ) {
                pid = pe.th32ProcessID;
                break;
            }
        } while ( Process32NextW ( snap , &pe ) );
    }
    CloseHandle ( snap );
    return pid;
}

struct vape_instance {
    void* base;
    uint32_t size_of_image;
};

int main ( ) {
    DWORD pid = find_minecraft ( );
    HANDLE h_proc = OpenProcess ( PROCESS_VM_READ | PROCESS_QUERY_INFORMATION , FALSE , pid );
    if ( !h_proc ) {
        printf ( "Failed to open PID %u (error %lu)\n" , pid , GetLastError ( ) );
        return 1;
    }

    printf ( "looking for vape v4\n" );

    MEMORY_BASIC_INFORMATION mbi = {};
    uint8_t* addr = nullptr;
    std::vector<vape_instance> found;

    while ( VirtualQueryEx ( h_proc , addr , &mbi , sizeof ( mbi ) ) ) {
        if ( mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.Type == MEM_PRIVATE && mbi.RegionSize >= 0x1000 ) {
            uint8_t hdr [ 0x600 ] = {};
            SIZE_T bytes_read = 0;
            if ( ReadProcessMemory ( h_proc , mbi.BaseAddress , hdr , sizeof ( hdr ) , &bytes_read ) && bytes_read >= 0x100 ) {
                if ( hdr [ 0 ] == 'M' && hdr [ 1 ] == 'Z' ) {
                    uint32_t e_lfanew = *( uint32_t* ) ( hdr + 0x3C );
                    if ( e_lfanew >= 0x40 && e_lfanew < 0x400 ) {
                        if ( *( uint32_t* ) ( hdr + e_lfanew ) == 0x4550 ) {
                            uint16_t num_sections = *( uint16_t* ) ( hdr + e_lfanew + 6 );
                            uint16_t opt_size = *( uint16_t* ) ( hdr + e_lfanew + 20 );
                            uint32_t size_of_img = *( uint32_t* ) ( hdr + e_lfanew + 24 + 56 );
                            uint32_t sec_off = e_lfanew + 24 + opt_size;
                            for ( int s = 0; s < num_sections && ( sec_off + 40 ) <= sizeof ( hdr ); s++ ) {
                                char name [ 9 ] = {};
                                memcpy ( name , hdr + sec_off , 8 );
                                if ( strcmp ( name , ".vlizer" ) == 0 ) {
                                    printf ( "vape v4 found @ %p\n" , mbi.BaseAddress );
                                    found.push_back ( { mbi.BaseAddress , size_of_img } );
                                    break;
                                }
                                sec_off += 40;
                            }
                        }
                    }
                }
            }
        }
        addr = ( uint8_t* ) mbi.BaseAddress + mbi.RegionSize;
    }

    if ( found.empty ( ) ) {
        printf ( "not found\n" );
        CloseHandle ( h_proc );
        getchar ( );
        return 0;
    }

    if ( found.size ( ) > 1 )
        printf ( "%llu instances found\n" , ( unsigned long long ) found.size ( ) );

    printf ( "dump? (y/n): " );
    char c = getchar ( );
    if ( c == 'y' || c == 'Y' ) {
        for ( size_t i = 0; i < found.size ( ); i++ ) {
            SIZE_T total_readable = 0;
            uint8_t* scan_addr = ( uint8_t* ) found [ i ].base;
            MEMORY_BASIC_INFORMATION scan_mbi = {};
            while ( VirtualQueryEx ( h_proc , scan_addr , &scan_mbi , sizeof ( scan_mbi ) ) ) {
                if ( scan_mbi.State != MEM_COMMIT ) break;
                if ( scan_mbi.AllocationBase != found [ i ].base ) break;
                total_readable += scan_mbi.RegionSize;
                scan_addr += scan_mbi.RegionSize;
                if ( total_readable >= found [ i ].size_of_image ) break;
            }
            if ( total_readable > found [ i ].size_of_image )
                total_readable = found [ i ].size_of_image;

            std::vector<uint8_t> buf ( total_readable );
            SIZE_T bytes_read = 0;
            ReadProcessMemory ( h_proc , found [ i ].base , buf.data ( ) , total_readable , &bytes_read );

            char filename [ 64 ];
            sprintf_s ( filename , "vape-V4-%llu.bin" , ( unsigned long long ) i );
            FILE* f = nullptr;
            fopen_s ( &f , filename , "wb" );
            if ( f ) {
                fwrite ( buf.data ( ) , 1 , bytes_read , f );
                fclose ( f );
                printf ( "dumped %s (0x%X bytes)\n" , filename , ( unsigned ) bytes_read );
            }
        }
    }

    CloseHandle ( h_proc );
    getchar ( );
    return 2;
}