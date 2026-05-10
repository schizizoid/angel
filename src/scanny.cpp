#include <iostream>
#include <fstream>
#include <sstream> 
#include <filesystem>
#include <vector>

struct Region {
    uintptr_t start_address;
    uintptr_t end_address;
};

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

int find_pid_by_name(const std::string& name) {

    // go trough each folder in /proc. if the process name equals the provides name > return the pid
    for (const auto& direntry : std::filesystem::directory_iterator("/proc/")) {
        try {
            int pid = std::stoi(direntry.path().filename().string());
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

    int pid = find_pid_by_name(name);

    std::cout << pid;

    std::vector regions = get_regions(pid);

    for(Region candidate_region : regions) {
        std::cout << candidate_region.start_address << " : " << candidate_region.end_address << std::endl;
    }


    return 0;
}