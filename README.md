# spine-code

This repository contains the P4 code that implements SPINE. The main files that implement SPINE are basic.p4 (P4 implementation for SPINE border routers) and controller.py (acts as the central controller and installs table rules). topology.json contains our testing topology. 

We relied heavily on the P4 tutorials found here: https://github.com/p4lang/tutorials in terms of structure and helper functions. All of the files in this repository except for the three mentioned above are from these P4 tutorials; we simply reproduce them here for convenience (i.e., you can clone this repository and should be able to compile the code directly).
