#ifndef __NKN_CHANNEL_H__
#define __NKN_CHANNEL_H__

#include <memory>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <chrono>

#include <spdlog/spdlog.h>

using namespace std;

namespace NKN {
    using namespace std::chrono;
    typedef chrono::seconds second;
    typedef chrono::milliseconds millisecond;

    template <typename ANY>
    class Channel {
    public:
    private:
        mutex _mutex;
        condition_variable cond_v;

        size_t capacity;
        queue<unique_ptr<ANY>> _queue;

    public:
        Channel(size_t size=1): capacity(size) {}
        ~Channel() {
            // spdlog::info("Channel<{}>.destructor():{} this[{}]", typeid(ANY).name(), __LINE__, (void *)this);
            unique_lock<decltype(_mutex)> lock(_mutex);
            if (!_queue.empty()) {
                spdlog::warn("Channel[{}]<{}> was destructed but buffer still have {} elements. Data will be lost!",
                        (void*)this, typeid(ANY).name(), _queue.size());
                if (!cond_v.wait_for(lock, millisecond(100), [this]{return _queue.empty();})) {
                    spdlog::warn("wait 100ms but the Channel[%p]<%s> still have %lu elements. Discarded it!",
                            (void*)this, typeid(ANY).name(), _queue.size());
                }
            }
        }

        bool push(unique_ptr<ANY> elem, bool nonblock=false, millisecond timeout=millisecond(0)) {
            // spdlog::info("Channel<{}>.push():{} this[{}]", typeid(ANY).name(), __LINE__, (void*)this);
            // timeout 0 as infinity
            auto deadline = timeout.count()==0 ? time_point<steady_clock>::max() : steady_clock::now() + timeout;
            unique_lock<decltype(_mutex)> lock(_mutex);
            if (_queue.size() >= capacity) {
                spdlog::warn("Channel[{}]<{}> full", (void*)this, typeid(ANY).name());
                if (nonblock)
                    return false;

                bool cond_succ = cond_v.wait_until(lock, deadline, [this]{return _queue.size() < capacity;});
                if (!cond_succ) {
                    if (steady_clock::now() < deadline){    // shoule not happen
                        spdlog::error("Channel[{}]<{}> occurred spurious wakeup. unreached deadline yet", (void*)this, typeid(ANY).name());
                    } else {
                        spdlog::warn("Channel[{}]<{}> still full after timeout", (void*)this, typeid(ANY).name());
                    }
                    return false;
                }
            }
            _queue.emplace(std::move(elem));
            cond_v.notify_all();
            return true;
        }

        unique_ptr<ANY> pop (bool nonblock=false, millisecond timeout=millisecond(0)) {
            // spdlog::info("Channel<{}>.pop({}):{} this[{}] with timeo [{}]", typeid(ANY).name(), nonblock, __LINE__, (void*)this, timeout.count());
            // timeout 0 as infinity
            auto deadline = timeout.count()==0 ? time_point<steady_clock>::max() : steady_clock::now() + timeout;
            unique_lock<decltype(_mutex)> lock(_mutex);
            if (_queue.empty()) {
                if (nonblock)
                    return nullptr;

                bool cond_succ = cond_v.wait_until(lock, deadline, [this]{return !_queue.empty();});
                if (!cond_succ) {
                    if (steady_clock::now() < deadline){    // shoule not happen
                        spdlog::error("Channel[{}]<{}> occurred spurious wakeup. unreached deadline deadline yet", (void*)this, typeid(ANY).name());
                    } else {
                        // fprintf(stderr, "Warning: Channel[%p]<%s> still empty after timeout\n", this, typeid(ANY).name());
                    }
                    return nullptr;
                }
            }
            auto ret = std::move(_queue.front());
            _queue.pop();
            cond_v.notify_all();
            // spdlog::info("Channel[{}]<{}> pop an elem {}", (void*)this, typeid(ANY).name(), *ret);
            return ret;
        }

        inline size_t size() {unique_lock<decltype(_mutex)> lock(_mutex); return _queue.size();}
    };
};  // namespace NKN
#endif  // __NKN_CHANNEL_H__
