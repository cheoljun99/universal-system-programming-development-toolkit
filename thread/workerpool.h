/*
 * Worker Pool Management Wrapper (WorkerPool Class)
 *
 * 본 구현은 여러 개의 Worker 스레드 객체(pthread 또는 std::thread 기반)를 관리하기 위한
 * 스레드 풀(thread pool) 관리 클래스이다. 각 Worker 인스턴스는 독립적으로 실행되며,
 * start_pool(), stop_pool(), monitor_pool() 메서드를 통해 전체 스레드의 수명과 상태를 제어한다.
 *
 * 특징:
 *  - 내부적으로 std::deque<Worker>를 사용하여 스레드 객체를 보관하고 관리한다.
 *  - 생성자에서 지정한 스레드 개수(thread_cnt)만큼 Worker 인스턴스를 생성 및 실행한다.
 *  - 모든 스레드는 독립적으로 start_thread() / stop_thread()를 통해 구동 및 정지한다.
 *  - 스레드 실행 중 예외가 발생하거나 종료된 경우, monitor_pool()에서 이를 감지하고
 *    자동으로 재시작(recovery) 시도를 수행한다.
 *  - RAII 원칙에 따라 객체 소멸 시 stop_pool()이 자동 호출되어
 *    모든 스레드 리소스를 안전하게 해제한다.
 *
 * start_pool() 동작:
 *  - 이미 실행 중인 풀(start_flag_ == true)일 경우 재호출할 수 없다.
 *  - 스레드 풀 생성 및 Worker 초기화를 수행하며, 하나라도 시작 실패 시 전체를 중단하고 stop_pool()을 호출한다.
 *
 * stop_pool() 동작:
 *  - 여러 번 호출되어도 안전하게 동작하도록 설계되어 있다.
 *  - 실행 중인 모든 Worker 스레드를 종료하고, 내부 컨테이너(workers_)를 정리한다.
 *  - 이미 정지된 상태에서 재호출되더라도 중복 해제나 오류가 발생하지 않는다.
 *
 * monitor_pool() 동작:
 *  - 스레드 풀 실행 상태를 주기적으로 점검하며, 종료된 스레드가 있을 경우 재시작을 시도한다.
 *  - 재시작(recovery)에 실패한 스레드가 존재할 경우 풀 전체를 중단(stop_pool())시킨다.
 *  - 라이브 스레드 수, 종료 스레드 수, 복구 성공/실패 개수를 출력하여 상태를 모니터링할 수 있다.
 *
 * 주의:
 *  - Worker 클래스는 반드시 start_thread(), stop_thread(), get_thread_term()을 제공해야 한다.
 *  - start_pool()과 stop_pool()은 스레드 풀의 명확한 수명 제어를 위해 외부에서 명시적으로 호출되어야 한다.
 *  - monitor_pool()은 주기적 감시용이며, 자동 복구 로직의 보조적 역할을 수행한다.
 *  - cleanup() 로직은 각 Worker 객체 내부에서 idempotent(중복 호출 시 안전)하게 설계되어야 한다.
 *
 * 본 클래스는 다중 스레드 환경에서의 안정적인 스레드 풀 운영과
 * 장애 복구 절차를 명확히 정의하기 위한 참조 수준의 관리 구현체이다.
 */

#pragma once

#include "Worker.h"
#include <iostream>
#include <deque>
#include <cstddef>
#include <atomic>

class WorkerPool {
private:
    std::deque<Worker> workers_; // Worker is pthread or std::thread
    std::atomic<bool> start_flag_;
    size_t thread_cnt_;
public:
    WorkerPool(size_t thread_cnt) : thread_cnt_(thread_cnt == 0 ? 1 : thread_cnt), start_flag_(false){}
    ~WorkerPool() {
        stop_pool();
    }
    bool start_pool(){
        if(start_flag_.load()==true){
            std::cerr << "[ERROR] already start thread pool "
			<< "(WorkerPool::start_pool) " << '\n';
			return false;
        }
        for (int i = 0; i < thread_cnt_; ++i) workers_.emplace_back();
        start_flag_.store(true);
        for(int i=0; i < thread_cnt_;i++){ 
            if(workers_[i].start_thread()==false){
                stop_pool();
                return false;
            }
        }
        return true;
    }
    void stop_pool(){
        if(start_flag_.load()==true){
            for(int i=0; i < thread_cnt_;++i){ 
                workers_[i].stop_thread();
            }
            workers_.clear();
            start_flag_.store(false);
        }
    }
    bool monitor_pool(){
        if(start_flag_.load()==false){
            std::cerr << "[ERROR] don't start thread pool "
			<< "(WorkerPool::start_pool) " << '\n';
            return false;
        }
        size_t dead_cnt=0;
        size_t recovery_fail_cnt=0;
        for(size_t i=0;i<thread_cnt_;++i){
            if(workers_[i].get_thread_term()){
                dead_cnt++;
                workers_[i].stop_thread();
                if(workers_[i].start_thread()==false){
                    recovery_fail_cnt++;
                }
            }
        }
        std::cout << "LIVE THREAD COUNT : "<< thread_cnt_- dead_cnt<<" "<<"DEAD THREAD COUNT : "<< dead_cnt<<" "
        <<"RECOVERY SUCCESS THREAD COUNT : "<<dead_cnt-recovery_fail_cnt<<" "<<"RECOVERY FAIL THREAD COUNT : "<<recovery_fail_cnt<<" \n";
        if(recovery_fail_cnt>0){
            stop_pool();
            return false;
        }
        return true;
    }
};