#include "stdafx.h"

#include <Psapi.h>

#include <GWCA/Utilities/Scanner.h>
#include <DbgHelp.h>
#include <GWCA/Utilities/Debug.h>

#pragma comment( lib, "dbghelp.lib" )

namespace {
    struct SectionOffset {
        uintptr_t start = 0;
        uintptr_t end = 0;
    };
    SectionOffset sections[3] = { 0 };

    std::string ucwords(const char* src) {
        const auto x = strlen(src);
        std::string dest = src;
        for (size_t i = 0; i < x; i++) {
            if (isalpha(dest[i]) && (i == 0 || !isalpha(dest[i-1]))) {
                dest[i] = (char)toupper(dest[i]);
            }
        }
        return dest;
    }
    std::string strtolower(const char* src) {
        const auto x = strlen(src);
        std::string dest = src;
        for (size_t i = 0; i < x; i++) {
            dest[i] = (char)tolower(dest[i]);
        }
        return dest;
    }

}
uintptr_t GW::Scanner::FindAssertion(const char* assertion_file, const char* assertion_msg, uint32_t line_number, int offset) {
    GWCA_ASSERT(assertion_file && *assertion_file);
    GWCA_ASSERT(assertion_msg && *assertion_msg);
    #pragma warning( push )
    #pragma warning( disable : 4838 )
    #pragma warning( disable : 4242 )
    #pragma warning( disable : 4244 )
    #pragma warning( disable : 4365 )
    int i;
    char assertion_bytes[] = "\x68????\xBA????\xB9????";
    char assertion_mask[] = "xxxxxxxxxxxxxxx";

    char* assertion_bytes_ptr = &assertion_bytes[5];
    char* assertion_mask_ptr = &assertion_mask[5];

    
    if (line_number) {
        if ((line_number & 0xff) == line_number) {
            // PUSH uint8
            assertion_bytes_ptr = &assertion_bytes[3];
            assertion_mask_ptr = &assertion_mask[3];
            assertion_bytes[3] = 0x6a;
            assertion_bytes[4] = line_number;
        }
        else {
            // PUSH uint32
            assertion_bytes_ptr = &assertion_bytes[0];
            assertion_mask_ptr = &assertion_mask[0];
            assertion_bytes[0] = 0x68;
            assertion_bytes[1] = line_number;
            assertion_bytes[2] = line_number >> 8;
            assertion_bytes[3] = line_number >> 16;
            assertion_bytes[4] = line_number >> 24;
        }
    }
    offset += &assertion_mask[5] - assertion_mask_ptr; // Legacy code meant that offsets are calculated from the \xBA instruction
    
    char assertion_message_mask[128];
    for (i = 0; assertion_msg[i]; i++) {
        assertion_message_mask[i] = 'x';
    }
    assertion_message_mask[i++] = 'x';
    assertion_message_mask[i] = 0;

    char assertion_file_mask[128];
    for (i = 0; assertion_file[i]; i++) {
        assertion_file_mask[i] = 'x';
    }
    assertion_file_mask[i++] = 'x';
    assertion_file_mask[i] = 0;
    
    uintptr_t start = 0;
    uintptr_t end = 0;

    Scanner::GetSectionAddressRange(Section::RDATA, &start, &end);

    uint32_t assertion_message_offset = start;
    uintptr_t found = 0;
    for (;;) {
        found = FindInRange(assertion_msg, assertion_message_mask, 0, assertion_message_offset, end);
        if (!found)
            break;

        assertion_message_offset = found + 1;

        assertion_bytes[11] = found;
        assertion_bytes[12] = found >> 8;
        assertion_bytes[13] = found >> 16;
        assertion_bytes[14] = found >> 24;

        uint32_t assertion_file_offset = start;
        for (;;) {
            found = FindInRange(assertion_file, assertion_file_mask, 0, assertion_file_offset, end);
            if (!found) {
                // try lower case file name
                found = FindInRange(strtolower(assertion_file).c_str(), assertion_file_mask, 0, assertion_file_offset, end);
            }
            if (!found) {
                // try camel case file name
                found = FindInRange(ucwords(assertion_file).c_str(), assertion_file_mask, 0, assertion_file_offset, end);
            }
            if (!found)
                break;

            assertion_file_offset = found + 1;

            // Find disk path colon minus one for find the start of the assertion string e.g. p:/
            if (((char*)found)[1] != ':') {
                found = FindInRange(":", "x", -0x1, found, found - 128);
                if (!found)
                    break;
            }

            assertion_bytes[6] = found;
            assertion_bytes[7] = found >> 8;
            assertion_bytes[8] = found >> 16;
            assertion_bytes[9] = found >> 24;

            found = Find(assertion_bytes_ptr, assertion_mask_ptr, offset);
            if (found)
                return found;
        }
    }
    return 0;
    #pragma warning(pop)
}
uintptr_t GW::Scanner::FindInRange(const char* pattern, const char* mask, int offset, DWORD start, DWORD end) {
    char first = pattern[0];
    size_t patternLength = strlen(mask ? mask : pattern);
    bool found = false;
    end -= patternLength;

    if (start > end) {
        // Scan backward
        for (DWORD i = start; i >= end; i--) {
            if (*(char*)i != first)
                continue;
            found = true;
            //For each byte in the pattern
            for (size_t idx = 0; idx < patternLength; idx++) {
                if ((!mask || mask[idx] == 'x') && pattern[idx] != *(char*)(i + idx)) {
                    found = false;
                    break;
                }
            }
            if (found)
                return i + offset;
        }
    }
    else {
        // Scan forward
        for (DWORD i = start; i < end; i++) {
            if (*(char*)i != first)
                continue;
            found = true;
            //For each byte in the pattern
            for (size_t idx = 0; idx < patternLength; idx++) {
                if ((!mask || mask[idx] == 'x') && pattern[idx] != *(char*)(i + idx)) {
                    found = false;
                    break;
                }
            }
            if (found)
                return i + offset;
        }
    }
    return NULL;
}
void GW::Scanner::GetSectionAddressRange(Section section, uintptr_t* start, uintptr_t* end) {
    if (start)
        *start = sections[section].start;
    if (end)
        *end = sections[section].end;
}
uintptr_t GW::Scanner::Find(const char* pattern, const char* mask, int offset, Section section) {
    return FindInRange(pattern, mask, offset, sections[section].start, sections[section].end);
}

bool GW::Scanner::IsValidPtr(uintptr_t address, Section section) {
    return address && address > sections[section].start && address < sections[section].end;
}

uintptr_t GW::Scanner::FunctionFromNearCall(uintptr_t call_instruction_address, bool check_valid_ptr) {
    if (!IsValidPtr(call_instruction_address,Section::TEXT))
        return 0;
    uintptr_t function_address = 0;
    switch (((*(uintptr_t*)call_instruction_address) & 0x000000ff)) {
    case 0xe8:   // CALL
    case 0xe9: { // JMP long
        const auto near_address = *(uintptr_t*)(call_instruction_address + 1);
        function_address = (near_address)+(call_instruction_address + 5);
    } break;
    case 0xeb: { // JMP short
        const auto near_address = *(char*)(call_instruction_address + 1);
        function_address = (near_address)+(call_instruction_address + 2);
    } break;
    default:
        return 0; // Not a near call instruction
    }
    if (check_valid_ptr && !IsValidPtr(function_address, Section::TEXT))
        return 0;
    // Check to see if there are any nested JMP's etc
    if (const auto nested_call = FunctionFromNearCall(function_address, check_valid_ptr)) {
        return nested_call;
    }
    return function_address;
}

uintptr_t GW::Scanner::ToFunctionStart(uintptr_t call_instruction_address, uint32_t scan_range) {
    return call_instruction_address ? FindInRange("\x55\x8b\xec", "xxx", 0, call_instruction_address, call_instruction_address - scan_range) : 0;
}

void GW::Scanner::Initialize(HMODULE hModule) {
    uint32_t dllImageBase = (uint32_t)hModule;
    IMAGE_NT_HEADERS* pNtHdr = ImageNtHeader(hModule);
    IMAGE_SECTION_HEADER* pSectionHdr = (IMAGE_SECTION_HEADER*)(pNtHdr + 1);
    //iterate through the list of all sections, and check the section name in the if conditon. etc
    for (int i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++)
    {
        char* name = (char*)pSectionHdr->Name;
        uint8_t section = 0x8;
        if (memcmp(name, ".text", 5) == 0)
            section = Section::TEXT;
        else if (memcmp(name, ".rdata", 6) == 0)
            section = Section::RDATA;
        else if (memcmp(name, ".data", 5) == 0)
            section = Section::DATA;
        if (section != 0x8) {
            sections[section].start = dllImageBase + pSectionHdr->VirtualAddress;
            sections[section].end = sections[section].start + pSectionHdr->Misc.VirtualSize;
        }
        pSectionHdr++;
    }
    if (!(sections[Section::TEXT].start && sections[Section::TEXT].end))
        throw 1;
}

void GW::Scanner::Initialize(const char* moduleName) {
    return Initialize(GetModuleHandleA(moduleName));
}

void GW::Scanner::Initialize(uintptr_t start, size_t size) {
    sections[Section::TEXT].start = start;
    sections[Section::TEXT].end = start + size;
}
