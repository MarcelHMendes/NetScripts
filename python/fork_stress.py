#!/usr/bin/python3

import threading
import time
import sys
import os

def work(thread_num, pid, delay):
    print("Thread %d from process %d" % (thread_num, pid))
    time.sleep(delay)

def main():

    if len(sys.argv) != 4:
        print("usage : fork_stress.py <n_forks> <n_threads> <delay_sleep>")
        sys.exit(0)
    n_forks = int(sys.argv[1]) - 1
    n_threads = int(sys.argv[2])
    delay_sleep = int(sys.argv[3])
    parent_pid = os.getpid()

    for i in range(n_forks):
        pid = os.getpid()
        if pid == parent_pid:
            try:
                process_type = os.fork()
            except OSError:
                raise OSError("Error forking process")
    #When parent processes dies, because of an OSError, child processes remain running

    threads_list = list()
    try:
        for i in range(n_threads):
            thread = threading.Thread(target=work, args=(i, pid, delay_sleep))
            thread.daemon = False
            thread.start()
            threads_list.append(thread)
    except RuntimeError:
        raise RuntimeError("Can't start new threads")
    #Threading interface links to pthreads, there is a chain from a Python thread to the kernel threads.
    #Python also has GIL guaranteeing that no two threads ever execute at the same time

    for thread in threads_list:
        thread.join()

    if process_type > 0:
        try:
            for _ in range(n_forks):
                os.wait()
        except ChildProcessError:
            raise ChildProcessError("No child processes")
    return 0

if __name__ == '__main__':
    sys.exit(main())
