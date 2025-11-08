#include <pthread.h>
#include <iostream>

class PthreadPool {
private:
    std::deque<Pthread> pthreads_;
    bool start_flag_;
    size_t thread_cnt_;
public:
    PthreadPool(size_t thread_cnt) : thread_cnt_(thread_cnt == 0 ? 1 : thread_cnt), start_flag_(false){}
    ~PthreadPool() {
        stop_pool();
    }
    bool start_pool(){
        if(start_flag_==true){
            std::cerr << "[ERROR] already start thread pool "
			<< "(PthreadPool::start_pool) " << '\n';
			return false;
        }
        for (int i = 0; i < thread_cnt_; ++i) pthreads_.emplace_back();
        for(int i=0; i < thread_cnt_;i++){ 
            if(pthreads_[i].start_thread()==false){
                stop_pool();
                return false;
            }
        }
        start_flag_=true;
        return true;
    }
    void stop_pool(){
        if(start_flag_==true){
            for(int i=0; i < thread_cnt_;++i){ 
                pthreads_[i].stop_thread();
            }
            pthreads_.clear();
            start_flag_ = false;
        }
    }
    bool monitor_pool(){
        if(start_flag_==false){
            std::cerr << "[ERROR] don't start thread pool "
			<< "(PthreadPool::start_pool) " << '\n';
            return false;
        }
        int dead_cnt=0;
        int recovery_fail_cnt=0;
        for(int i=0;i<thread_cnt_;++i){
            if(pthreads_[i].get_thread_term()){
                dead_cnt++;
                pthreads_[i].stop_thread();
                if(pthreads_[i].start_thread()==false){
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
}