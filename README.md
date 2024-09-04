# xdn-ebpf

This research aimed at finding the latency for eBPF when capturing the state differences of a blackbox application. The prototype is designed as a proof-of-concept model for an edge approach to CDNs. I worked under the supervision and guidance of PhD candidate Fadhil Kurnia of UMass Amherst. 

The approach of this research involved having the eBPF capture the system calls produced by a target blackbox application. After capturing the desired system calls (open, write), its information is passed onto a driver program through eBPF ring-buffers. The driver program continously listened to any changes produced in the ring-buffer, recording each one as it occurs. This recording process allows for the replication of the target application thereby producing a possible edge approach to content delivery networks (CDN).

The result of this research 
