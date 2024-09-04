# xdn-ebpf

## Abstract
This research aimed at finding the latency for eBPF when capturing the state differences of a blackbox application. The prototype is designed as a proof-of-concept model for an edge approach to CDNs. I worked under the supervision and guidance of PhD candidate Fadhil Kurnia of UMass Amherst. 

## Method
The approach of this research involved having the eBPF capture the system calls produced by a target black box application. After capturing the desired system calls (open, write), its information is passed onto a driver program through eBPF ring-buffers. The driver program continuously listened to any changes produced in the ring-buffer, recording each one as it occurred. This recording process allows for the replication of the target application thereby producing a possible edge approach to content delivery networks (CDN).

To measure the latency of the application with and without eBPF, the ```time``` command was used. The latency measurement for no-eBPF is simply done by executing the bash file ```./run_curl.sh (target URL)```, where the target URL here was a simple web application (flask-example.py). The bash file repeats 1000 ```time``` commands, each measuring the latency for retrieving local data. This data produces a txt file ```times.txt```. Once execution is completed, the ```measurer.py``` program is executed which produces 3 statistics: mean, median, p95.

For measurement with eBPF, the PID of the target application is identified. With the PID, it is passed on to the driver program as a parameter: ```./minimal (PID)```. This enables the eBPF to trace the intended program, capturing all the necessary system calls. Then, conduct identical process as above.


## Result
The latency recorded with and without eBPF revealed a mean time of 8.389ms and 7.681ms, respectively.

![alt text](https://github.com/faizfrds/xdn-ebpf/)

## Conclusion

The measured times demonstrated an overhead of 0.708ms. This result brings us a step closer to uncovering the possible edge approach in CDNs. With the sub-millisecond overhead, it gives great confidence in the research that edge approaches in CDN is not too distant.


