# ICMP_Loki_Attack
ICMP_Loki_Attack is an open source tool, primarily aimed to penetration testers and developers. ICMP_Loki_Attack is using the Scapy framework to network penetration. It can be used from a Windows 7.

# Usage
How to:

```
usage: ICMP_Loki_Attack.py [-h] [-I IP] [-F FILENAME] [-L] [-C FILESIZECOUNT]

optional arguments:
  -h, --help                                       show this help message and exit
  -I IP, --ip IP                                   Source & Destination ip
  -F FILENAME, --fileName FILENAME                 Send & Receive FileName
  -L, --loseData                                   LoseData Send & Receive
  -C FILESIZECOUNT, --fileSizeCount FILESIZECOUNT  FileSize Count Check
```                   

# Examples:

```
 ICMP_Loki_Attack -C FileName
 ICMP_Loki_Attack -I 127.0.0.1 -F FileName
 ICMP_Loki_Attack -I 127.0.0.1 -F FileName -L
```

# Installation
To install ICMP_Loki_Attack you just need to clone it from git and run it:
```
  git clone https://github.com/nam3z1p/ICMP_Loki_Attack.git
        
  python ICMP_Loki_Attack.py -h
```

# Pre-requisites
To use ICMP_Loki_Attack you need to have Scapy installed on your python environment. The easiest way to install Scapy on your python is using pip:

```
pip install scapy
```
More information on how to install Scapy can be found [here](https://scapy.net/)

# Disclaimer
This is version of the software, so I expect some bugs to be present
I am not a developer, so my coding skills might not be the best
This tool has been tested on a Windows 7.

Any suggestions and comments are welcome!
