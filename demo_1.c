
#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/io.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

//defined for accessing the PCI config space
#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

//callbakc config -when virtio is found
typedef void (*virtio_device_callback_t)(uint8_t bus, uint8_t slot, uint8_t func, uint16_t vendor_id, uint16_t device_id);


//generate address to acccess PCI
uint32_t pci_config_read(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t address = (1 << 31) | (bus << 16) | (slot << 11) | (func << 8) | (offset & 0xFC); // address to access PCI
    outl(address, PCI_CONFIG_ADDRESS); //read address
    return inl(PCI_CONFIG_DATA);
}

//finding PCI device address
void pci_scan(virtio_device_callback_t callback) {
    for (uint8_t bus = 0; bus < 256; bus++) {
        for (uint8_t slot = 0;  slot < 32; slot++) {
            for (uint8_t func = 0; func < 8; func++) {
                uint32_t vendor_device = pci_config_read(bus, slot, func, 0x00);
                uint16_t vendor_id = vendor_device & 0xFFFF;
                uint16_t device_id = vendor_device >> 16;

               // uint16_t device_id - cendro_device

                //invalid
                if (vendor_id == 0xFFFF) continue;

                printf("Bus: %02X, Slot: %02X, Func: %02X, Vendor ID: %04X, Device ID: %04X\n",
                       bus, slot, func, vendor_id, device_id);

                if (vendor_id == 0x1AF4) { 
                    printf("  --> Virtio Device Found!\n");
                   
                    if (callback) {
                        callback(bus, slot, func, vendor_id, device_id);
                    }
                }
            }
        }
    }
}


void* map_pci_device_memory(uint32_t base_addr, size_t size) {
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd == -1) {
        perror("open");
        return NULL;
    }

    void* mapped_addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, base_addr);
    if (mapped_addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return NULL;
    }

    close(fd);
    return mapped_addr;
}


void unmap_pci_device_memory(void* addr, size_t size) {
    if (munmap(addr, size) == -1) {
        perror("munmap");
    }
}


void virtio_device_found(uint8_t bus, uint8_t slot, uint8_t func, uint16_t vendor_id, uint16_t device_id) {
    printf("Notification: Virtio device found at Bus: %02X, Slot: %02X, Func: %02X, Vendor ID: %04X, Device ID: %04X\n",
           bus, slot, func, vendor_id, device_id);

   
    uint32_t base_addr = 0xF0000000; // Example base address
    size_t size = 0x1000; 

    // Map the device memory
    void* mapped_addr = map_pci_device_memory(base_addr, size);
    if (mapped_addr) {
        // Perform read/write operations on the mapped memory
        // Example: Write a value to the first register
        *((volatile uint32_t*)mapped_addr) = 0x12345678;

        // Example: Read a value from the first register
        uint32_t value = *((volatile uint32_t*)mapped_addr);
        printf("Read value: 0x%08X\n", value);

        // Unmap the device memory
        unmap_pci_device_memory(mapped_addr, size);
    }
}

int main() {
    // Request I/O permissions
    if (iopl(3) < 0) {
        perror("iopl");
        return 1;
    }

    printf("Scanning PCI devices...\n");
    // Pass the callback function to pci_scan
    pci_scan(virtio_device_found);

    return 0;
}