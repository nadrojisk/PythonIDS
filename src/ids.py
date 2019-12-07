import nmap_ids
import ettercap_ids
import multiprocessing
import responder_ids

"""
Main IDS Driver

Author: Jordan Sosnowski, Charles Harper
Date: Dec 6, 2019
"""

t1 = multiprocessing.Process(
    target=nmap_ids.xmas_signature_detection, kwargs={'interface': 'eth0', 'continuous': True})
t2 = multiprocessing.Process(
    target=nmap_ids.ack_signature_detection, kwargs={'interface': 'eth0', 'continuous': True})
t3 = multiprocessing.Process(
    target=nmap_ids.syn_signature_detection, kwargs={'interface': 'eth0', 'continuous': True})
t4 = multiprocessing.Process(
    target=ettercap_ids.heuristic_detection, kwargs={'interface': 'eth0', 'continuous': True})
t5 = multiprocessing.Process(
    target=ettercap_ids.behavioral_detection, kwargs={'interface': 'eth0', 'continuous': True})
t6 = multiprocessing.Process(
    target=responder_ids.behavioral_detection, kwargs={'interface': 'eth0', 'continuous': True})



# starting thread 1
t1.start()
# starting thread 2
t2.start()
# starting thread 3
t3.start()
# starting thread 4
t4.start()
# starting thread 5
t5.start()
# starting thread 6
t6.start()


# wait until thread 1 is completely executed
t1.join()
# wait until thread 2 is completely executed
t2.join()
# wait until thread 3 is completely executed
t3.join()
# wait until thread 4 is completely executed
t4.join()
# wait until thread 5 is completely executed
t5.join()
# wait until thread 6 is completely executed
t6.join()
# both threads completely executed
print("Done!")
