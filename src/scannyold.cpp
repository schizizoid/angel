#include <iostream>
#include <string>
#include <sys/uio.h>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <vector>
#include <limits>
#include <thread>
#include <atomic>

#include <imgui/imgui.h>


struct MemoryRegion {
    uintptr_t start;
    uintptr_t end;
};

template<typename T>
T read_address(pid_t pid, uintptr_t address) {
    T value;
    struct iovec local_iov = {&value, sizeof(T)};
    struct iovec remote_iov = {(void*)address, sizeof(T)};
    if (process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) > 0) return value;
    return T();
}

template<typename T>
void write_address(pid_t pid, uintptr_t address, T value) {
    struct iovec local_iov = {&value, sizeof(T)};
    struct iovec remote_iov = {(void*)address, sizeof(T)};
    process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
}

std::vector<MemoryRegion> get_valid_regions(pid_t pid) {
    std::vector<MemoryRegion> regions;
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream maps(maps_path);
    if (!maps.is_open()) return regions;
    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream iss(line);
        std::string addr_range, perms;
        iss >> addr_range >> perms;
        if (perms.find('r') == std::string::npos || perms.find('w') == std::string::npos) continue;
        size_t dash = addr_range.find('-');
        regions.push_back({std::stoull(addr_range.substr(0, dash), nullptr, 16),
                          std::stoull(addr_range.substr(dash + 1), nullptr, 16)});
    }
    return regions;
}

template<typename T>
void scan_and_filter(pid_t pid) {
    std::cout << "[e]xact, [u]nknown, [b]etween: ";
    char mode; std::cin >> mode;
    
    auto regions = get_valid_regions(pid);
    if (regions.empty()) {
        std::cout << "Failed to read process memory regions\n";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return;
    }
    
    const size_t CHUNK_SIZE = 1024 * 1024;
    std::vector<uintptr_t> candidates;
    std::vector<T> old_values;
    T target = 0;
    T min_val = 0, max_val = 0;
    
    if (mode == 'e') {
        std::cout << "Value: "; std::cin >> target;
    } else if (mode == 'b') {
        std::cout << "Min: "; std::cin >> min_val;
        std::cout << "Max: "; std::cin >> max_val;
    }
    
    for (const auto& region : regions) {
        size_t region_size = region.end - region.start;
        for (size_t offset = 0; offset < region_size; offset += CHUNK_SIZE) {
            size_t chunk_size = std::min(CHUNK_SIZE, region_size - offset);
            char* buffer = new char[chunk_size];
            struct iovec local_iov = {buffer, chunk_size};
            struct iovec remote_iov = {(void*)(region.start + offset), chunk_size};
            ssize_t bytes = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
            if (bytes > 0) {
                for (size_t i = 0; i <= bytes - sizeof(T); i += sizeof(T)) {
                    T* value = (T*)(buffer + i);
                    if (mode == 'e' && *value == target) {
                        candidates.push_back(region.start + offset + i);
                    } else if (mode == 'b' && *value >= min_val && *value <= max_val) {
                        candidates.push_back(region.start + offset + i);
                        old_values.push_back(*value);
                    } else if (mode == 'u') {
                        candidates.push_back(region.start + offset + i);
                        old_values.push_back(*value);
                    }
                }
            }
            delete[] buffer;
        }
    }
    
    if (candidates.empty()) {
        std::cout << "No addresses found\n";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return;
    }
    
    std::cout << "Found " << candidates.size() << " addresses\n";
    
    std::atomic<bool> freeze_running{false};
    std::thread freeze_thread;
    
    while (true) {
        if (candidates.size() <= 10) {
            for (auto addr : candidates) {
                std::cout << "0x" << std::hex << addr << std::dec << " = " << read_address<T>(pid, addr) << "\n";
            }
        }
        
        std::cout << "[f]ilter, [w]rite, [z]freeze, [v]iew live, [a]dd address, [d]iscard scan: ";
        char action; std::cin >> action;
        
        if (action == 'd') {
            std::cout << "Discarding scan...\n";
            if (freeze_running) {
                freeze_running = false;
                if (freeze_thread.joinable()) freeze_thread.join();
            }
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            return;
        }
        
        if (action == 'v') {
            std::cout << "Viewing live (press Enter to stop)...\n";
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            
            std::atomic<bool> viewing{true};
            std::thread view_thread([&]() {
                while (viewing) {
                    std::cout << "\033[2J\033[H";
                    for (size_t i = 0; i < std::min(candidates.size(), size_t(50)); i++) {
                        std::cout << "0x" << std::hex << candidates[i] << std::dec << " = " << read_address<T>(pid, candidates[i]) << "\n";
                    }
                    if (candidates.size() > 50) {
                        std::cout << "... (" << candidates.size() - 50 << " more)\n";
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            });
            
            std::cin.get();
            viewing = false;
            if (view_thread.joinable()) view_thread.join();
            continue;
        }
        
        if (action == 'a') {
            std::cout << "Address with optional offset (e.g., '0x1234' or '0x1234+4'): ";
            std::string addr_input;
            std::cin >> addr_input;
            
            uintptr_t base_addr;
            int offset = 0;
            
            size_t plus_pos = addr_input.find('+');
            size_t minus_pos = addr_input.find('-');
            
            if (plus_pos != std::string::npos) {
                base_addr = std::stoull(addr_input.substr(0, plus_pos), nullptr, 16);
                offset = std::stoi(addr_input.substr(plus_pos + 1));
            } else if (minus_pos != std::string::npos) {
                base_addr = std::stoull(addr_input.substr(0, minus_pos), nullptr, 16);
                offset = -std::stoi(addr_input.substr(minus_pos + 1));
            } else {
                base_addr = std::stoull(addr_input, nullptr, 16);
            }
            
            uintptr_t final_addr = base_addr + offset;
            candidates.push_back(final_addr);
            old_values.push_back(read_address<T>(pid, final_addr));
            
            std::cout << "Added 0x" << std::hex << final_addr << std::dec << " = " << read_address<T>(pid, final_addr) << "\n";
            std::cout << candidates.size() << " total addresses\n";
            continue;
        }
        
        if (action == 'z') {
            if (!freeze_running) {
                freeze_running = true;
                freeze_thread = std::thread([&]() {
                    while (freeze_running) {
                        for (size_t i = 0; i < candidates.size() && freeze_running; i++) {
                            write_address<T>(pid, candidates[i], old_values[i]);
                        }
                    }
                });
                std::cout << "Freezing " << candidates.size() << " addresses. Press 'z' again to stop.\n";
            } else {
                freeze_running = false;
                if (freeze_thread.joinable()) freeze_thread.join();
                std::cout << "Freeze stopped.\n";
            }
            continue;
        }
        
        if (action == 'w') {
            std::cout << "New value: ";
            std::string input;
            std::cin >> input;
            
            for (size_t i = 0; i < candidates.size(); i++) {
                T current = read_address<T>(pid, candidates[i]);
                T new_value;
                
                if (input[0] == '+' || input[0] == '-') {
                    T offset = static_cast<T>(std::stof(input));
                    new_value = current + offset;
                } else {
                    new_value = static_cast<T>(std::stof(input));
                }
                
                write_address<T>(pid, candidates[i], new_value);
            }
            std::cout << "Written to " << candidates.size() << " addresses\n";
            continue;
        }
        
        std::cout << "Filter: [e]xact, [i]ncreased, [d]ecreased, [u]nchanged, [b]etween, [n]arrow: ";
        std::cin >> mode;
        
        if (mode == 'n') {
            std::cout << "Narrow amount (e.g., '25%' or '100'): ";
            std::string narrow_input;
            std::cin >> narrow_input;
            
            size_t narrow_count;
            if (narrow_input.back() == '%') {
                float percentage = std::stof(narrow_input.substr(0, narrow_input.size() - 1));
                narrow_count = static_cast<size_t>((percentage / 100.0f) * candidates.size());
            } else {
                narrow_count = std::stoull(narrow_input);
            }
            
            narrow_count = std::min(narrow_count, candidates.size());
            if (narrow_count == 0) {
                std::cout << "Invalid narrow amount\n";
                continue;
            }
            
            std::cout << "Modify value (e.g., '+1', '-5', '100'): ";
            std::string modify_input;
            std::cin >> modify_input;
            
            std::cout << "Modifying first " << narrow_count << " addresses...\n";
            for (size_t i = 0; i < narrow_count; i++) {
                T current = read_address<T>(pid, candidates[i]);
                T new_value;
                
                if (modify_input[0] == '+' || modify_input[0] == '-') {
                    T offset = static_cast<T>(std::stof(modify_input));
                    new_value = current + offset;
                } else {
                    new_value = static_cast<T>(std::stof(modify_input));
                }
                
                write_address<T>(pid, candidates[i], new_value);
            }
            
            std::cout << "Test in game. Did the behavior change? [y]es (keep these) / [n]o (remove these): ";
            char response;
            std::cin >> response;
            
            std::vector<uintptr_t> new_candidates;
            std::vector<T> new_old_values;
            
            if (response == 'y') {
                for (size_t i = 0; i < narrow_count; i++) {
                    new_candidates.push_back(candidates[i]);
                    new_old_values.push_back(read_address<T>(pid, candidates[i]));
                }
                std::cout << "Kept first " << narrow_count << " addresses\n";
            } else {
                for (size_t i = narrow_count; i < candidates.size(); i++) {
                    new_candidates.push_back(candidates[i]);
                    new_old_values.push_back(old_values[i]);
                }
                std::cout << "Removed first " << narrow_count << " addresses\n";
            }
            
            candidates = new_candidates;
            old_values = new_old_values;
            
            if (candidates.empty()) {
                std::cout << "No addresses left\n";
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                return;
            }
            
            std::cout << candidates.size() << " addresses remaining\n";
            continue;
        }
        
        if (mode == 'e') { 
            std::cout << "Value: "; std::cin >> target; 
        } else if (mode == 'b') {
            std::cout << "Min: "; std::cin >> min_val;
            std::cout << "Max: "; std::cin >> max_val;
        }
        
        std::vector<uintptr_t> new_candidates;
        std::vector<T> new_old_values;
        for (size_t j = 0; j < candidates.size(); j++) {
            T value = read_address<T>(pid, candidates[j]);
            bool keep = false;
            if (mode == 'e') keep = (value == target);
            else if (mode == 'i') keep = (value > old_values[j]);
            else if (mode == 'd') keep = (value < old_values[j]);
            else if (mode == 'u') keep = (value == old_values[j]);
            else if (mode == 'b') keep = (value >= min_val && value <= max_val);
            
            if (keep) {
                new_candidates.push_back(candidates[j]);
                new_old_values.push_back(value);
            }
        }
        candidates = new_candidates;
        old_values = new_old_values;
        
        if (candidates.empty()) {
            std::cout << "No matching addresses\n";
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            return;
        }
        
        std::cout << candidates.size() << " left\n";
    }
    
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

int main() {
    while (true) {
        std::cout << "PID: "; 
        pid_t pid; 
        std::cin >> pid;
        std::cout << "[i]nt or [f]loat: "; 
        char type; 
        std::cin >> type;
        if (type == 'i') scan_and_filter<int>(pid);
        else scan_and_filter<float>(pid);
    }
}