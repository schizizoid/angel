#include <iostream>
#include <fstream>
#include <sstream> 
#include <filesystem>
#include <vector>
#include <sys/uio.h>
#include <cmath>

//debug functions:
template<typename T>
void print_value(std::string string, T value) {
    std::cout << string << value << std::endl;
}

template<typename T>
void print(T value) {
    std::cout << value << std::endl;
}

struct Region {
    uintptr_t start_address;
    uintptr_t end_address;
};

void read_address(pid_t pid, uintptr_t address) {
    float value;

    iovec local;
    local.iov_base = &value;
    local.iov_len = sizeof(float);

    iovec remote;
    remote.iov_base = (void*)address;
    remote.iov_len = sizeof(float);

    process_vm_readv(pid, &local, 1, &remote, 1, 0);
    std::cout << "value: " << value << std::endl;
}

void write_address(pid_t pid, uintptr_t address, float value) {
    iovec local;
    local.iov_base = &value;
    local.iov_len = sizeof(float);

    iovec remote;
    remote.iov_base = (void*)address;
    remote.iov_len = sizeof(float);

    process_vm_writev(pid, &local, 1, &remote, 1, 0);
    std::cout << "value: " << value << std::endl;
}

// initial scan. use only once
std::vector<uintptr_t> scan_regions(pid_t pid, std::vector<Region> regions, float value) {
    std::vector<uintptr_t> valid_addresses;

    size_t buffer_size = 1024 * 1024;
    std::vector<char> buffer(buffer_size);

    for(Region region : regions) {
        size_t region_size = region.end_address - region.start_address;

        iovec local;
        local.iov_base = buffer.data();

        iovec remote;

        int chunks = std::ceil((float)region_size / (float)buffer_size);

        size_t remaining_bytes = region_size;
        for(int i = 0 ; i < chunks; i++) {
            size_t chunk_size = std::min(buffer_size, remaining_bytes);

            local.iov_len = chunk_size;

            remote.iov_base = (void*)(region.start_address + buffer_size * i);
            remote.iov_len = chunk_size;

            process_vm_readv(pid, &local, 1, &remote, 1, 0);

            //region.start_address + (buffer_size * i) + j

            for(int j = 0; j < chunk_size - sizeof(float); j+=4) {
                float* f = (float*)&buffer[j]; // looks scary, just gives the float value of a position in the buffer
                if(*f == value) {
                    uintptr_t address = region.start_address + (buffer_size * i) + j;
                    valid_addresses.push_back(address);
                }
            }

            remaining_bytes -= chunk_size;
        }
    }
    return valid_addresses;
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

    print_value("pid: ", pid);

    std::vector regions = get_regions(pid);

    std::cout << "whatcha wanna write: ";
    float value;
    std::cin >> value;

    std::vector<uintptr_t> addresses = scan_regions(pid, regions, value);

    print("reading scanned data");

    for(uintptr_t address : addresses) {
        write_address(pid, address, 13);
    }

    // for(Region candidate_region : regions) {
    //     std::cout << candidate_region.start_address << " : " << candidate_region.end_address << std::endl;
    // }

    // std::cout << "address?:\n";

    // std::string address_s;
    // std::cin >> address_s;
    // uintptr_t addr = std::stoull(address_s, nullptr, 16);

    

    // std::cout << std::hex << addr << std::dec;

    // read_address(pid, addr);

    // std::cout << "whatcha wanna write: \n";
    // float value;
    // std::cin >> value;

    // write_address(pid, addr, value);

    return 0;
}

//0x7ffc9b9865b4