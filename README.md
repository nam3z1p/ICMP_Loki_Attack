# ICMP_Loki_Attack
Fridump (v0.1) is an open source memory dumping tool, primarily aimed to penetration testers and developers. Fridump is using the Frida framework to dump accessible memory addresses from any platform supported. It can be used from a Windows, Linux or Mac OS X system to dump the memory of an iOS, Android or Windows application.

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

  git clone https://github.com/nam3z1p/ICMP_Loki_Attack.git
        
  python ICMP_Loki_Attack.py -h
  
# Pre-requisites
To use ICMP_Loki_Attack you need to have Scapy installed on your python environment. The easiest way to install Scapy on your python is using pip:

pip install frida
More information on how to install Frida can be found here

For iOS, installation instructions can be found here.

For Android, installation instructions can be found here.

Note: On Android devices, make sure that the frida-server binary is running as root!

# Disclaimer
This is version 0.1 of the software, so I expect some bugs to be present
I am not a developer, so my coding skills might not be the best
This tool has been tested on a Windows 7.

Any suggestions and comments are welcome!
