#include <iostream>
#include <fstream>
#include <sstream> 
#include <filesystem>
#include <vector>
#include <sys/uio.h>
#include <cmath>
#include <thread>
#include <fcntl.h>
#include <unistd.h>

//debug functions:
template<typename T>
void print_value(std::string string, T value) {
    std::cout << string << value << std::endl;
}

template<typename T>
void print(T value) {
    std::cout << value << std::endl;
}

struct address_t {
    uintptr_t address;
    float value;
};

struct Region {
    uintptr_t start_address;
    uintptr_t end_address;
};

float read_address(pid_t pid, uintptr_t address) {
    float value;

    iovec local;
    local.iov_base = &value;
    local.iov_len = sizeof(float);

    iovec remote;
    remote.iov_base = (void*)address;
    remote.iov_len = sizeof(float);

    process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return value;
}

void write_address(pid_t pid, uintptr_t address, float value) {
    iovec local;
    local.iov_base = &value;
    local.iov_len = sizeof(float);

    iovec remote;
    remote.iov_base = (void*)address;
    remote.iov_len = sizeof(float);

    process_vm_writev(pid, &local, 1, &remote, 1, 0);
}

bool is_page_present(int pagemap_fd, uintptr_t address) {
    uint64_t page_index = address / 4096;
    off_t offset = page_index * 8;

    uint64_t entry;
    ssize_t bytes = pread(pagemap_fd, &entry, sizeof(entry), offset);

    if(bytes != sizeof(entry)) return false; // read failed or short read

    return (entry >> 63) & 1;
}

// initial scan. use only once
std::vector<address_t> scan_regions(pid_t pid, std::vector<Region> regions, uint8_t scantype, float value = 0.0f) {
    std::vector<address_t> valid_addresses;

    int pagemap_fd = open(("/proc/" + std::to_string(pid) + "/pagemap").c_str(), O_RDONLY);
    if(pagemap_fd == -1) {
        std::cout << "FAILED to open pagemap!" << std::endl;
        return valid_addresses;
    }

    const size_t page_size = 4096;
    std::vector<char> buffer(page_size);

    size_t pages_checked = 0;
    size_t pages_present = 0;
    size_t reads_failed = 0;

    for(Region region : regions) {
        for(uintptr_t page_addr = region.start_address; page_addr < region.end_address; page_addr += page_size) {
            pages_checked++;

            if(!is_page_present(pagemap_fd, page_addr)) continue;
            pages_present++;

            iovec local;
            local.iov_base = buffer.data();
            local.iov_len = page_size;

            iovec remote;
            remote.iov_base = (void*)page_addr;
            remote.iov_len = page_size;

            ssize_t bytes_read = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if(bytes_read <= 0) { reads_failed++; continue; }

            for(size_t j = 0; j < page_size - sizeof(float); j += 4) {
                float* f = (float*)&buffer[j];

                switch(scantype) {
                    case 0x1:
                        if(std::abs(*f - value) < 0.001f) {
                            valid_addresses.push_back({page_addr + j, *f});
                        }
                        break;
                    case 0x2:
                        if(*f != 0.0f && *f > -1000.0f && *f < 1000.0f) {
                            valid_addresses.push_back({page_addr + j, *f});
                        }
                        break;
                }
            }
        }
    }

    close(pagemap_fd);

    std::cout << "pages checked: " << pages_checked << std::endl;
    std::cout << "pages present: " << pages_present << std::endl;
    std::cout << "reads failed on present pages: " << reads_failed << std::endl;

    return valid_addresses;
}

//use after the initial scan is done ^
void rescan(pid_t pid, std::vector<address_t>& valid_addresses, uint8_t scantype, float value = 0.0f) {
    std::vector<address_t> new_valid_addresses;

    switch (scantype)
    {
    case 0x1: //exact
        for (address_t& address : valid_addresses) {
            float current_value = read_address(pid, address.address);
            if(std::abs(current_value - value) < 0.001f) {
                address.value = current_value;
                new_valid_addresses.push_back(address);
            }
        }
        break;
    case 0x2: // increased
        for (address_t& address : valid_addresses) {
            float current_value = read_address(pid, address.address);
            if(current_value > address.value) {
                address.value = current_value;
                new_valid_addresses.push_back(address);
            }
        }
        break;
    case 0x3: // decreased
        for (address_t& address : valid_addresses) {
            float current_value = read_address(pid, address.address);
            if(current_value < address.value) {
                address.value = current_value;
                new_valid_addresses.push_back(address);
            }
        }
        break;
    case 0x4: // unchanged
        for (address_t& address : valid_addresses) {
            float current_value = read_address(pid, address.address);
            if(std::abs(current_value - address.value) < 0.001f) {
                address.value = current_value;
                new_valid_addresses.push_back(address);
            }
        }
        break;
    }

    valid_addresses = new_valid_addresses;
    new_valid_addresses.clear();
    new_valid_addresses.shrink_to_fit();
}

std::vector<Region> get_regions(pid_t pid) {

    std::vector<Region> regions;

    // read maps file
    std::ifstream file("/proc/" + std::to_string(pid) + "/maps");

    std::string line;
    while(std::getline(file, line)) {

        // go trough each line and take first 2 parts (addr range and permissions)
        std::istringstream parse(line);
        std::string addr_range, perms;
        parse >> addr_range >> perms;

        // if its the right permissions > parse the addr range into 2 uintptr_t
        if(perms == "rw-p") {
            std::string first = addr_range.substr(0, addr_range.find('-'));
            std::string last = addr_range.substr(addr_range.find('-')+1);

            Region candidate_region;
            candidate_region.start_address = std::stoull(first, nullptr, 16);
            candidate_region.end_address = std::stoull(last, nullptr, 16);

            regions.push_back(candidate_region);
        }
    }

    return regions;
}

pid_t find_pid_by_name(const std::string& name) {

    // go trough each folder in /proc. if the process name equals the provides name > return the pid
    for (const auto& direntry : std::filesystem::directory_iterator("/proc/")) {
        try {
            pid_t pid = std::stoi(direntry.path().filename().string());
            std::ifstream file("/proc/" + std::to_string(pid) + "/comm");
            std::string proc_name;
            std::getline(file, proc_name);
            if (proc_name == name) {
                return pid;
            }            
        }
        catch (const std::invalid_argument& e) {
            continue;
        }
    }
    return -1;
}

int main() {
    std::cout << "find pid by name!!: ";

    std::string name;
    std::cin >> name;

    pid_t pid = find_pid_by_name(name);

    if(pid == -1) { print("program not found"); return -1; }

    while(true) {
        std::cout << "initialscan: exact value (e), unkown value (u)";
        char option;
        std::cin >> option;

        std::vector regions = get_regions(pid);
        size_t total = 0;
        for(auto& r : regions) total += (r.end_address - r.start_address);
        std::cout << "total rw region size: " << total << " bytes" << std::endl;

        float value;
        uint8_t scantype = 0x1;

        switch (option)
        {
        case 'e':
            std::cout << "exact initial scan value (float): ";
            std::cin >> value;
            
            break;
        
        case 'u':
            scantype = 0x2;
            break;
        }
        
        std::vector<address_t> addresses = scan_regions(pid, regions, scantype, value);

        while(true)
        {
            print_value("amount of matches: ", addresses.size());
            std::cout << "write valid addresses (w), rescan current for new value (r) cancel scan (c): ";
            char option;
            std::cin >> option;

            if(option == 'w') {
                std::cout << "watcha wanna write?: ";
                std::cin >> value;
                for(address_t address : addresses) {
                    value += read_address(pid, address.address);
                    write_address(pid, address.address, value);
                }
            }
            else if(option == 'r') {
                std::cout << "how ya wanna scan: exact (e), increased (i), decreased (d), unchanged (u)";
                char option;
                std::cin >> option;

                scantype = 0x1;
                switch (option)
                {
                case 'e':
                    std::cout << "wats the new value?: ";
                    std::cin >> value;
                    break;
                case 'i':
                    scantype = 0x2;
                    break;
                case 'd':
                    scantype = 0x3;
                    break;
                case 'u':
                    scantype = 0x4;
                    break;
                }

                rescan(pid, addresses, scantype, value);
            }
            else if(option == 'c') {
                break;
            }
        }
        break;
    }
    return 0;
}

//0x7ffc9b9865b4