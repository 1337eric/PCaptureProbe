# PCaptureProbe
Usage - python PcapProbe.py {PCAPFILE}

Uses Scapy to loop through every individual packet, and if there are certain flags it will raise a level of suspicion and it will determine if its an attack or not.

If it is an attack on the network it will describe how to fix it

This can be implimented into a linux server along side of a traffic monitoring program, once the traffic has entered a certain threshold of packets, it will automatically capture it and run it with PCapture Probe, then PCapture Probe will tell the user how to patch it

In the future I am planning to add:
  - TCP Flag attack recognition, such as URG, SYN, ACK, SYN + ACK, etc.
  - Checksum Checks (Marking Traffic with invalid checksums)
  - Automatic Firewall implementation
  - Faster processing time for instant attack patches
 
Demonstrations: <br>
[![Attack1-Demonstration.png](https://i.postimg.cc/pXBhXt9r/Attack1-Demonstration.png)](https://postimg.cc/zVVX06FY)
[![Attack2-Demonstration.png](https://i.postimg.cc/qB1HkbJ0/Attack2-Demonstration.png)](https://postimg.cc/NL2zDx2P)
