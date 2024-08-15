import subprocess
import time
import multiprocessing

binary_path = "./hello-x86_64"
num_processes = 8

def run_binary(start_time, stats_interval, count):
    try:
        while True:
            subprocess.run(binary_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            with count.get_lock():
                count.value += 1

            if count.value % stats_interval == 0:
                elapsed_time = time.time() - start_time.value
                if elapsed_time > 0:
                    executions_per_second = count.value / elapsed_time
                    print(f"fps: {executions_per_second:.2f}")

    except KeyboardInterrupt:
        elapsed_time = time.time() - start_time.value
        if elapsed_time > 0:
            executions_per_second = count.value / elapsed_time
            print(f"fps: {executions_per_second:.2f}")

def start_process(start_time, stats_interval, count):
    run_binary(start_time, stats_interval, count)

if __name__ == "__main__":
    start_time = multiprocessing.Value('d', time.time())
    stats_interval = 0xFFF
    count = multiprocessing.Value('i', 0)
    processes = []

    for _ in range(num_processes):
        p = multiprocessing.Process(target=start_process, args=(start_time, stats_interval, count))
        p.start()
        processes.append(p)

    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        for p in processes:
            p.terminate()

        for p in processes:
            p.join()

    

