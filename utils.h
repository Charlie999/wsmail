//
// Created by charlie on 22/04/2021.
//

#ifndef SMTPOVERHTTPS_UTILS_H
#define SMTPOVERHTTPS_UTILS_H

#include <cstdlib>
#include <memory>

template <typename T>
bool is_uninitialized(std::weak_ptr<T> const& weak) {
    using wt = std::weak_ptr<T>;
    return !weak.owner_before(wt{}) && !wt{}.owner_before(weak);
}

std::string replace_all(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}

std::mutex log_lock;

int sync_printf(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    log_lock.lock();
    int ret = vprintf(format, args);
    log_lock.unlock();

    va_end(args);
    return ret;
}

template <typename Out>
void split(const std::string &s, char delim, Out result) {
    std::istringstream iss(s);
    std::string item;
    while (std::getline(iss, item, delim)) {
        *result++ = item;
    }
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

#endif //SMTPOVERHTTPS_UTILS_H
