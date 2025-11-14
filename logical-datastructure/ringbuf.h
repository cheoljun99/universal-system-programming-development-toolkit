/*
 * RingBuf: 고정 크기 순환 버퍼(Ring Buffer) 구현
 *
 * 구현 개요:
 *  - Slot 단위로 데이터를 저장하는 구조로, 각 Slot은 길이(len_)와 최대 65535바이트의 데이터를 보유
 *  - 내부적으로 head/tail 인덱스와 cnt(요소 개수)를 이용해 순환 구조를 유지
 *  - 버퍼 크기는 자동으로 2의 거듭제곱 형태로 보정되어 비트 마스크(&) 기반 인덱스 연산을 수행
 *
 * 주요 기능:
 *  - push_infinite(): 버퍼가 가득 찰 경우 가장 오래된 데이터를 덮어쓰며 새 데이터 삽입
 *  - push_finite(): 버퍼가 가득 차면 삽입 실패(RING_PULL 반환)
 *  - pop(): 가장 오래된 데이터를 읽고 제거
 *  - empty(): 버퍼가 비어 있는지 여부 확인
 *
 * 메모리 관리:
 *  - std::unique_ptr<Slot[]>을 이용해 동적 메모리를 안전하게 관리
 *  - 복사/이동 생성자 및 대입 연산자 모두 명시적으로 정의되어 자원 소유권 및 깊은 복사 보장
 *
 * 설계 특성:
 *  - 버퍼 크기는 자동으로 2의 거듭제곱으로 조정되어 인덱스 wrap-around 시 마스크 연산 사용
 *  - 단일 스레드 환경 기준으로 설계됨 (멀티스레드 사용 시 외부 동기화 필요)
 *  - memcpy 기반의 고정 슬롯형 구조로, 데이터 블록 단위 저장에 최적화
 *  - 메모리 복사 오버헤드 외에 별도의 잠금(lock)이나 커널 개입 없음
 *
 * 사용 예시:
 *  RingBuf ring(128);
 *  uint8_t data[10] = {0,1,2,3,4,5,6,7,8,9};
 *  ring.push_infinite(data, 10);
 *  uint8_t out[10];
 *  ring.pop(out, 10);
 */

#pragma once

#include <cstring>  
#include <cstdint>
#include <memory>

#define MAX_SLOT_SIZE 65535

#define RING_PULL -1

struct Slot {
    uint16_t len_;
    uint8_t slot_[MAX_SLOT_SIZE];
};

class RingBuf {
private:
    std::unique_ptr<Slot[]> buf_;
    size_t head_;
    size_t tail_;
    size_t cnt_;
    size_t size_;
public:
    RingBuf(size_t size): head_(0),tail_(0),cnt_(0){
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

    RingBuf(const RingBuf& oth)
        : buf_(std::make_unique<Slot[]>(oth.size_)),
          head_(oth.head_),
          tail_(oth.tail_),
          cnt_(oth.cnt_),
          size_(oth.size_) {
            std::memcpy(buf_.get(), oth.buf_.get(), sizeof(Slot) * size_);
        }
    RingBuf& operator=(const RingBuf& oth) {
        if (this == &oth) return *this;
        buf_ = std::make_unique<Slot[]>(oth.size_);
        size_ = oth.size_;
        head_ = oth.head_;
        tail_ = oth.tail_;
        cnt_ = oth.cnt_;
        std::memcpy(buf_.get(), oth.buf_.get(), sizeof(Slot) * size_);
            return *this;
        }
    RingBuf(RingBuf&& oth)
        : buf_(std::move(oth.buf_)),
          head_(oth.head_),
          tail_(oth.tail_),
          cnt_(oth.cnt_),
          size_(oth.size_) {
            oth.head_ = oth.tail_ = oth.cnt_ = oth.size_ = 0;
        }
    RingBuf& operator=(RingBuf&& oth) noexcept {
        if (this != &oth) {
            buf_ = std::move(oth.buf_);
            head_ = oth.head_;
            tail_ = oth.tail_;
            cnt_ = oth.cnt_;
            size_ = oth.size_;
            oth.head_ = oth.tail_ = oth.cnt_ = oth.size_ = 0;
        }
        return *this;
    }
    int32_t push_infinite(const uint8_t* new_slot, size_t len) {
        if(len > MAX_SLOT_SIZE) len = MAX_SLOT_SIZE;
        if (cnt_ == size_) {// 버퍼가 가득 찬 경우 가장 오래된 데이터 덮어쓰기
            head_ = (head_ + 1) & (size_ - 1);
            cnt_--;
        }
        buf_[tail_].len_ = static_cast<uint16_t>(len);
        std::memcpy(buf_[tail_].slot_, new_slot, len);
        tail_ = (tail_ + 1) & (size_ - 1);
        cnt_++;
        return static_cast<int32_t>(len);
    }
    int32_t push_finite(const uint8_t* new_slot, size_t len) {// push_finite (패킷 추가, 가득 차면 false 리턴 드랍)
        if(len > MAX_SLOT_SIZE) len = MAX_SLOT_SIZE;
        if (cnt_ == size_) {
            return RING_PULL; // 가득 찼음
        }
        buf_[tail_].len_ = static_cast<uint16_t>(len);
        std::memcpy(buf_[tail_].slot_, new_slot, len);
        tail_ = (tail_ + 1) & (size_ - 1);
        cnt_++;
        return static_cast<int32_t>(len);
    }
    int32_t pop(uint8_t* out, size_t len) {
        if (cnt_ == 0) return 0;
        if(len > buf_[head_].len_) len = buf_[head_].len_;
        std::memcpy(out, buf_[head_].slot_, len);
        head_ = (head_ + 1) & (size_ - 1);
        cnt_--;
        return static_cast<int32_t>(len);
    }
    bool empty() const {
        return cnt_ == 0;
    }
};