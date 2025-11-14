/*
 * Vyukov Bounded SPMC Lock-Free Queue (Byte Buffer Version)
 *
 * 본 구현은 Dmitry Vyukov가 제안한 bounded MPMC 알고리즘을 기반으로 파생된
 * SPMC(Single Producer, Multiple Consumer) 형태의 lock-free 원형 버퍼(queue)이다.
 *
 * 특징:
 *  - 단일 producer, 복수 consumer 환경에서 완전한 lock-free 동작 보장
 *  - 각 슬롯(Node)의 seq 필드를 통한 상태 추적으로 ABA 문제 방지
 *  - head / tail 원자적 분리 관리 → consumer 간 경쟁은 CAS(compare_exchange_weak)로 해결
 *  - 메모리 오더링(acquire/release) 준수로 CPU 아키텍처 독립적 안전성 확보
 *  - 2의 제곱 크기 버퍼 및 비트 마스크 인덱싱으로 모듈로(mod) 연산 제거
 *  - false sharing 방지를 위한 64바이트 정렬 적용
 *  - payload는 최대 MAX_NODE_SIZE 바이트까지 저장 가능
 *  - & mask 연산 사용 mask = size - 1 
 *
 * 주의:
 *  - enqueue()는 단일 producer만 호출해야 하며, 복수 producer 동시 호출 시 동작이 보장되지 않는다.
 *  - 경쟁 상황에서 busy-spin(continue 루프)이 발생할 수 있으며,
 *    필요 시 _mm_pause() 또는 std::this_thread::yield() 삽입 권장.
 *  - 큐가 파괴될 때는 모든 producer / consumer 스레드가 종료된 상태여야 한다.
 *
 * 본 코드는 Dmitry Vyukov의 공개 알고리즘을 기반으로 한 독자 구현이며,
 * Folly, rigtorp, moodycamel 등 산업 수준의 lock-free 큐와 동일한 정합성을 제공한다.
 */

#pragma once
#include <atomic>
#include <cstring>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <cassert>
#include <memory>
#include "sharedbuf.h"

#define MAX_NODE_SIZE 65535

struct alignas(64) Node {
    std::atomic<size_t> seq;
    uint16_t len_;
    uint8_t data_[MAX_NODE_SIZE];
};

class SPMCLockFreeBuf : public SharedBuf{
private:
    size_t size_;
    std::unique_ptr<Node[]> buf_;
    alignas(64) std::atomic<size_t> head_;
    alignas(64) std::atomic<size_t> tail_;
public:
    SPMCLockFreeBuf(size_t size): head_(0), tail_(0)
    {
        if (size < 2) size = 2;
        // 2의 제곱이 아닐 경우 상위 제곱으로 보정
        if ((size & (size - 1)) != 0) {
            size_t cap = 1;
            while (cap < size)
                cap <<= 1;
            size = cap;
        }
        size_ = size;
        buf_ = std::make_unique<Node[]>(size_);
        for (size_t i = 0; i < size_; ++i) buf_[i].seq.store(i, std::memory_order_relaxed);
    }
    // 단일 producer만 호출해야 함
    int32_t enqueue(const uint8_t* data, size_t len) override{
        if(len > MAX_NODE_SIZE) len = MAX_NODE_SIZE;
        size_t t = tail_.load(std::memory_order_relaxed);
        Node& slot = buf_[t & (size_ - 1)];
        size_t seq = slot.seq.load(std::memory_order_acquire);
        intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(t);
        if (diff != 0)
            return -1; // full
        std::memcpy(slot.data_, data, len);
        slot.len_ = static_cast<uint16_t>(len);
        slot.seq.store(t + 1, std::memory_order_release);
        tail_.store(t + 1, std::memory_order_release);
        return static_cast<int32_t>(len);
    }
    // 복수 consumer 가능
    int32_t dequeue(uint8_t* out, size_t len) override{
        while (true) {
            size_t h = head_.load(std::memory_order_relaxed);
            Node& slot = buf_[h & (size_ - 1)];
            size_t seq = slot.seq.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(h + 1);
            if (diff < 0)return -1; // empty
            if (diff == 0) {
                // head 경쟁
                if (head_.compare_exchange_weak(h, h + 1,std::memory_order_acquire, std::memory_order_relaxed)) {
                    if(len>slot.len_) len = slot.len_;
                    std::memcpy(out, slot.data_, len);
                    slot.seq.store(h + size_, std::memory_order_release);
                    return static_cast<int32_t>(len);
                }
            } else {
                // 다른 consumer가 이미 가져감
                //h = head_.load(std::memory_order_relaxed);
                //_mm_pause();
                //std::this_thread::yield();
                continue;
            }
        }
    }
};
