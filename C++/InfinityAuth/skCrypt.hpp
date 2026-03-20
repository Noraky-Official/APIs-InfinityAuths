#pragma once
#include <string>

template <typename T>
class skCrypt {
public:
    skCrypt(T data) : _data(data) {}
    T decrypt() { return _data; }
private:
    T _data;
};
