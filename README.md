# Enumeraga

Automatic enumeration tool written in Go that wraps Linux tools, ported from my tool [autoEnum](https://github.com/0x5ubt13/autoenum), originally written in Bash. This is an attempt to develop a rich tool that leverages the features of Go.

~~~
demo gif coming as soon as this works!
~~~

## Usage

Give it either a single IP address or a file containing a list of IPs, a name to use for the output files, sit back, and relax:

~~~
┌──(kali㉿SubtleLabs)-[~]
└─$ enumeraga -h   
 __________                                    ______________________
 ___  ____/__________  ________ __________________    |_  ____/__    |
 __  __/  __  __ \  / / /_  __ `__ \  _ \_  ___/_  /| |  / __ __  /| |
 _  /___  _  / / / /_/ /_  / / / / /  __/  /   _  ___ / /_/ / _  ___ |
 /_____/  /_/ /_/\__,_/ /_/ /_/ /_/\___//_/    /_/  |_\____/  /_/  |_|
                            by 0x5ubt13

[*] Help flag detected. Aborting other checks and printing usage.

Usage: enumeraga [-abhq] [-d value] [-o value] [-p value] [-r value] [-t value] [parameters ...]
 -a, --again        Repeat the scan and compare with initial ports discovered.
 -b, --brute        Activate all fuzzing and bruteforcing in the script.
 -d, --DNS=value    Specify custom DNS servers. Default option: -n
 -h, --help         Display this help and exit.
 -o, --output=value
                    Select a different base folder for the output.
                    [/tmp/autoEnum_output]
 -p, --top=value    Run port sweep with nmap and the flag --top-ports=<your
                    input>
 -q, --quiet        Don't print the banner and decrease overall verbosity.
 -r, --range=value  Specify a CIDR range to use tools for whole subnets
 -t, --target=value
                    Specify target single IP / List of IPs file.
~~~

## The name

Doing a casual search looking for my tool, I found out that the name autoEnum was already taken by a tool also written in Bash doing similar things developed years ago, so I decided to give my tool a different name. I thought of this version as the third iteration of the program, being the first one [autoNmap](https://github.com/0x5ubt13/myToolkit/tree/main/autoNmap), and the second one [autoEnum](https://github.com/0x5ubt13/autoenum). 

The next name had to be some sort of third iteration. It was quite fun and creative trying to come up with a new name, and after brainstorming several possibilities, I tried Pokémon, but I could not think of cool name for a second "evolution" using "auto" as a prefix. It made sense borrowing from the spell naming convention of the Final Fantasy universe, which also includes a G in the third version of their spells, and so to honour the decision to use Go, and develop the third stage of a script that does automatic enumeration for you, Enumeraga was born.

## Quality and Learning-As-You-Go

This is my first serious tool developed in Go. At the time of creating this repo, I have been learning Golang for the best part of the last 2 years, and I have been using it to develop solutions for the [Advent of Code](https://adventofcode.com/). 

Although I will try my best to adhere to coding conventions, I am still learning as I code, and any kind of contribution towards quality will always be welcome.

## The motivation

Working as pentesters, or playing CTFs, or fiddling around with practice labs, we come across the same initial phases of recon and enumeratino over and over again. I thought it would be an amazing opportunity to practice my coding skills if I automated the initial tools that I always run. Then, after seeing the first results, I liked what I had done and kept adding on more features, until the Bash script grew up so much that I started thinking: "what if I actually use Go and compile this to a binary? Would I be able to pull it off?"... And, well, I am a sucker for a good challenge if learning is a joyful side effect.

## Wrapped tools currently present

- Braa
- CeWL
- CrackMapExec
- Enum4linux
- Ffuf
- Fping
- Gobuster
- Hydra
- Ident-user-enum
- Metasploit
- Nbtscan-unixwiz
- Nikto
- Nmap
- Nmblookup
- Ldapsearch
- ODAT
- Onesixtyone
- Responder-RunFinger
- RPCDump
- Rusers
- Rwho
- SMBMap
- SNMPWalk
- SSH-Audit
- WPScan
- Xsltproc
- WhatWeb
- WafW00f

## To Do

---
AutoEnum:
- [x] Implement optional arguments
- [x] Experiment with nice colours
- [x] Implement the use of `printf` instead of `echo`
- [x] Adapt to Google's shell scripting style guide
- [x] Implement sending notifications when tools have finished on background
- [x] Hide many of the notifications behind an optional verbose flag
- [x] Finish the core script
---
Enumeraga:
- [ ] Port all of this to Golang
- [ ] Test thoroughly
- [ ] Link each wrapped tool on README to their official repos
- [ ] Containerise
- [ ] Improve the way output is presented to terminal
- [ ] Improve README.md to show all protocols the script enumerates
- [ ] Add MOAR enum tools
- [ ] Enumerate all things (legally!)

Happy enumeration!


