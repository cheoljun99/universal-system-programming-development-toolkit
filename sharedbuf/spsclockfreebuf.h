/*
 * Lamport Bounded SPSC Lock-Free Queue (Byte Buffer Version)
 *
 * 본 구현은 Leslie Lamport가 제안한 bounded SPSC(Single Producer, Single Consumer)
 * ring buffer 알고리즘을 기반으로 한 lock-free 큐이다.
 *
 * 특징:
 *  - 단일 producer, 단일 consumer 환경에서 완전한 wait-free 동작 보장
 *  - CAS(compare_exchange) 연산이 필요 없음
 *  - head / tail 인덱스만 원자적으로 관리 → 최소한의 메모리 배리어 사용
 *  - acquire/release 오더링을 통해 CPU 아키텍처 간 일관성 유지
 *  - 2의 제곱 크기 버퍼와 비트 마스크 인덱싱으로 모듈로(mod) 연산 제거
 *  - false sharing 방지를 위한 64바이트 정렬 권장
 *  - & mask 연산 사용 mask = size - 1 
 *
 * 주의:
 *  - producer 및 consumer 스레드는 각각 단일해야 한다.
 *  - 큐가 가득 찼을 때 push()는 -1을 반환하며, 데이터는 버려진다.
 *  - 큐가 비었을 때 pop()은 -1을 반환한다.
 *  - 멀티스레드 환경에서 push/pop을 동시에 호출하지 않으면 lock-free 특성이 사라진다.
 *  - 절대 SPSC 구조외에는 사용하지 말 것.
 *  - 절대적인 안전성은 SPSC 구조일때만 보장.
 *
 * 본 코드는 Lamport의 고전적인 SPSC 큐 알고리즘을 C++ 메모리 모델에 맞게 구현한 형태로,
 * 고속 통신 버퍼, 오디오 스트림, 네트워크 패킷 큐 등 실시간 처리용으로 적합하다.
 */

#pragma once

#include <cstring>  
#include <cstdint>
#include <atomic>
#include <vector>
#include <memory>
#include "sharedbuf.h"

#define MAX_SLOT_SIZE 65535

struct Slot {
    uint16_t len_;
    uint8_t data_[MAX_SLOT_SIZE];
};

class SPSCLockFreeBuf : public SharedBuf{
private:
    std::unique_ptr<Slot[]> buf_;
    std::atomic<size_t> head_;
    std::atomic<size_t> tail_;
    size_t size_;
public:
    SPSCLockFreeBuf(size_t size): head_(0),tail_(0){
        if (size < 2) size = 2;
        if ((size & (size - 1)) != 0) {// 2의 제곱이 아닐 경우 상위 제곱으로 보정
            size_t cap = 1;
            while (cap < size)
                cap <<= 1;
            size = cap;
        }
        size_ = size;
        buf_=std::make_unique<Slot[]>(size_);
    }
    int32_t enqueue(const uint8_t* data, size_t len) override{
        if(len > MAX_SLOT_SIZE) len = MAX_SLOT_SIZE;
        size_t head = head_.load(std::memory_order_relaxed);
        size_t next = (head + 1) & (size_ - 1);
        if (next == tail_.load(std::memory_order_acquire)) return -1; // full
        std::memcpy(buf_[head].data_, data, len);
        buf_[head].len_ = static_cast<uint16_t>(len);
        head_.store(next, std::memory_order_release);
        return static_cast<int32_t>(len);
    }
    int32_t dequeue(uint8_t* out, size_t len) override{
        size_t tail = tail_.load(std::memory_order_relaxed);
        if (tail == head_.load(std::memory_order_acquire)) return -1; // empty
        if(len > buf_[tail].len_) len = buf_[tail].len_;
        std::memcpy(out,buf_[tail].data_,len);
        tail_.store((tail + 1) & (size_ - 1), std::memory_order_release);
        return static_cast<int32_t>(len);
    }
};