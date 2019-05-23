# spine-code

This repository contains the P4 code that implements SPINE. The main files that implement SPINE are basic.p4 (P4 implementation for SPINE border routers) and controller.py (acts as the central controller and installs table rules). topology.json contains our testing topology. switch.p4 is a P4 implementation for an unmodified v4 switch (e.g., to model a switch in the untrusted entity). 

The four files mentioned above rely heavily on the P4 tutorials found at https://github.com/p4lang/tutorials in terms of structure and basic P4 setup. All of other files in this repository Iin the utils folder) are directly copied from these P4 tutorials; we simply reproduce them here for convenience (i.e., you can clone this repository and should be able to compile the code directly).
