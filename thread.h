#pragma once
#include <thread>
#include <atomic>
#include <exception>
#include <iostream>
#include <cstring>

class Thread {
private:
    std::thread thread_;
    std::atomic<bool> thread_term_;
public:
    Thread() : thread_term_(false) {}
    ~Thread() { stop_thread(); }
    bool start_thread() {
        if (thread_.joinable()) {
            std::cerr << "[ERROR] already started thread "
                << "(Thread::start_thread) "
                << "thread(ID : " << std::this_thread::get_id() << ")\n";
            return false;
        }
        if (!setup()) {
            cleanup();
            return false;
        }
        thread_ = std::thread(&Thread::thread_func, this);
        return true;
    }
    void stop_thread() {
        if (thread_.joinable()) {
            if (!thread_term_.load()) {
                thread_term_.store(true);
            }
            thread_.join();
        }
        cleanup();
    }
    bool get_thread_term() { return thread_term_.load();}
private:
    bool setup();
    void cleanup();
    static void thread_func(Thread* self) {
        std::cout << "thread(ID : " << std::this_thread::get_id()<< ") start...\n";
        try { self->thread_loop(); }
        catch (const std::exception& e) {
            std::cerr << "[EXCEPT] thread exception: " << e.what() << '\n';
            self->thread_term_.store(true);
        }
        std::cout << "thread(ID : " << std::this_thread::get_id()<< ") stop!!!\n";
    }
    void thread_loop();
};