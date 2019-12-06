import nmap_ids
import multiprocessing

t1 = multiprocessing.Process(
    target=nmap_ids.xmas_signature_detection, kwargs={'interface': 'eth0', 'continous': True})
t2 = multiprocessing.Process(
    target=nmap_ids.ack_signature_detection, kwargs={'interface': 'eth0', 'continous': True})
t3 = multiprocessing.Process(
    target=nmap_ids.syn_signature_detection, kwargs={'interface': 'eth0', 'continous': True})


# starting thread 1
t1.start()
# starting thread 2
t2.start()
# starting thread 2
t3.start()

# wait until thread 1 is completely executed
t1.join()
# wait until thread 2 is completely executed
t2.join()
# wait until thread 2 is completely executed
t3.join()

# both threads completely executed
print("Done!")
