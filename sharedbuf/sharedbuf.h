#pragma once
#include <cstddef>
#include <cstdint>

class SharedBuf {
public:
    virtual ~SharedBuf() = default;

    // 데이터 삽입, 성공 시 실제 삽입된 길이 반환, 실패 시 -1 반환
    virtual int32_t enqueue(const uint8_t* data, size_t len) = 0;

    // 데이터 추출, 성공 시 추출된 길이 반환, 실패 시 -1 반환
    virtual int32_t dequeue(uint8_t* out, size_t len) = 0;

};
