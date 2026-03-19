#pragma once

// small task scheduler tuned for bounded parallelism during multi-engine scans.
#include <algorithm>
#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

struct SchedulerProfile
{
    unsigned int logicalCores = 1;
    unsigned int recommendedWorkers = 1;
    unsigned int heavyFileWorkers = 1;
    bool parallelEnabled = false;
    std::string label;
};

inline SchedulerProfile DetectSchedulerProfile()
{
    SchedulerProfile profile;
    profile.logicalCores = std::max(1u, std::thread::hardware_concurrency());
    profile.parallelEnabled = profile.logicalCores > 1;

    if (profile.logicalCores <= 2)
    {
        profile.recommendedWorkers = 1;
        profile.heavyFileWorkers = 1;
        profile.label = "Low-core compatibility profile";
    }
    else if (profile.logicalCores <= 4)
    {
        profile.recommendedWorkers = std::min(3u, profile.logicalCores);
        profile.heavyFileWorkers = profile.recommendedWorkers;
        profile.label = "Balanced quad-core profile";
    }
    else if (profile.logicalCores <= 8)
    {
        profile.recommendedWorkers = std::max(3u, profile.logicalCores - 1u);
        profile.heavyFileWorkers = std::min(profile.logicalCores, 6u);
        profile.label = "Mainstream multi-core profile";
    }
    else
    {
        profile.recommendedWorkers = std::max(4u, std::min(profile.logicalCores - 1u, 12u));
        profile.heavyFileWorkers = std::max(4u, std::min(profile.logicalCores, 16u));
        profile.label = profile.logicalCores >= 16 ? "High-parallel desktop profile" : "Enthusiast multi-core profile";
    }

    return profile;
}

inline unsigned int ChoosePipelineWorkerCount(const SchedulerProfile& profile, bool heavyFileMode)
{
    if (!profile.parallelEnabled)
        return 1u;
    return heavyFileMode ? profile.heavyFileWorkers : profile.recommendedWorkers;
}

class AdaptiveTaskScheduler
{
public:
    explicit AdaptiveTaskScheduler(unsigned int workerCount)
        : stop_(false)
    {
        const unsigned int actualWorkers = std::max(1u, workerCount);
        workers_.reserve(actualWorkers);
        for (unsigned int i = 0; i < actualWorkers; ++i)
            workers_.emplace_back([this]() { WorkerLoop(); });
    }

    AdaptiveTaskScheduler(const AdaptiveTaskScheduler&) = delete;
    AdaptiveTaskScheduler& operator=(const AdaptiveTaskScheduler&) = delete;

    ~AdaptiveTaskScheduler()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_ = true;
        }
        cv_.notify_all();

        for (auto& worker : workers_)
        {
            if (worker.joinable())
                worker.join();
        }
    }

    template <typename Fn>
    auto Submit(Fn&& fn) -> std::future<typename std::invoke_result_t<Fn>>
    {
        using Result = typename std::invoke_result_t<Fn>;

        auto task = std::make_shared<std::packaged_task<Result()>>(std::forward<Fn>(fn));
        std::future<Result> future = task->get_future();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push([task]() { (*task)(); });
        }

        cv_.notify_one();
        return future;
    }

    unsigned int WorkerCount() const
    {
        return static_cast<unsigned int>(workers_.size());
    }

private:
    void WorkerLoop()
    {
        for (;;)
        {
            std::function<void()> task;

            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this]() { return stop_ || !queue_.empty(); });

                if (stop_ && queue_.empty())
                    return;

                task = std::move(queue_.front());
                queue_.pop();
            }

            task();
        }
    }

    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool stop_;
};

template <typename Fn>
inline auto LaunchAdaptiveTask(bool enabled, Fn&& fn) -> std::future<decltype(fn())>
{
    if (enabled)
        return std::async(std::launch::async, std::forward<Fn>(fn));
    return std::async(std::launch::deferred, std::forward<Fn>(fn));
}
