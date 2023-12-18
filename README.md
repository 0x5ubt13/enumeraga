<img src="img/Enumeraga-logo_transparent.png" align="left" width="130" height="130"/>

# Enumeraga - Hack your initial scans

[![Go Report Card](https://goreportcard.com/badge/github.com/0x5ubt13/enumeraga)](https://goreportcard.com/report/github.com/0x5ubt13/enumeraga)
[![Maintainability](https://api.codeclimate.com/v1/badges/a26c3b3db97f4a3fdeef/maintainability)](https://codeclimate.com/github/0x5ubt13/enumeraga/maintainability)
[![GoDoc](https://godoc.org/github.com/0x5ubt13/enumeraga?status.svg)](https://godoc.org/github.com/0x5ubt13/enumeraga)
![License](https://img.shields.io/github/license/0x5ubt13/enumeraga?color=blue)

Automatic multiprocess Linux CLI tool that aims for a quick enumeration wrapping pentesting tools. Scan your target in 20 seconds! This is an attempt to develop a rich tool that leverages the nice features Go has to offer. Containerised version coming soon :eyes:

![Enumeraga demo gif](./img/enumeraga_demo_gif_v0.1.4-beta.gif)

## The motivation

Working as pentesters, or playing CTFs, or fiddling around with practice labs, we come across the same initial phases of recon and enumeration over and over again. Or how many times we have to spawn a new clean testing machine and reinstall everything? I thought it would be an amazing opportunity to practice my coding skills if I automated the installation process and the initial tools that I always run in new engagements. Then, after seeing the first results in Bash (if you're curious: [autoEnum](https://github.com/0x5ubt13/autoenum)), I liked what I had done, and I kept adding on more features, until the Bash script grew up so much that I started thinking: "what if I actually use Go and compile this to a binary? Would I be able to pull it off...?" And, well, I'm a sucker for a good challenge if learning is a joyful side effect.

## Flow chart

![Enumeraga flow chart](./img/enumeraga_flowchart_v2.jpg)

## Usage

Give `Enumeraga` either a single IP address or a file containing a list of IPs. Sit back, relax, and laugh maniacally while it handles all enumeration for you, going through every open port on your target on your behalf:

    ┌──(root㉿SubtleLabs)-[~]
    └─# enumeraga -h

                                                          v0.1.14-beta
     __________                                    ______________________
     ___  ____/__________  ________ __________________    |_  ____/__    |
     __  __/  __  __ \  / / /_  __ `__ \  _ \_  ___/_  /| |  / __ __  /| |
     _  /___  _  / / / /_/ /_  / / / / /  __/  /   _  ___ / /_/ / _  ___ |
     /_____/  /_/ /_/\__,_/ /_/ /_/ /_/\___//_/    /_/  |_\____/  /_/  |_|
                            by 0x5ubt13
    
    
    [*] ---------- Starting checks phase ----------
    [*] Help flag detected. Aborting other checks and printing usage.
    
    Usage: enumeraga [-bhiqV] [-o value] [-p value] [-r value] [-t value] [parameters ...]
     -b, --brute        Activate all fuzzing and bruteforcing in the script.
     -h, --help         Display this help and exit.
     -i, --install      Only try to install pre-requisite tools and exit.
     -o, --output=value
                        Select a different base folder for the output.
                        [/tmp/enumeraga_output]
     -p, --top-ports=value
                        Run port sweep with nmap and the flag --top-ports=<your
                        input>
     -q, --quiet        Don't print the banner and decrease overall verbosity.
     -r, --range=value  Specify a CIDR range to use tools for whole subnets.
     -t, --target=value
                        Specify target single IP / List of IPs file.
     -V, --vv           Flood your terminal with plenty of verbosity!

## Installation

### Executable version, get latest release

Simply grab the executable and launch it at your leisure! All the necessary tools to run that might be missing in your distro should be directly installed (if `Enumeraga` has your consent), otherwise it will prompt you to install it manually and exit.

This program has been developed in a Kali distro on WSL, so for maximum compatibility I'd suggest it's also run on a Kali VM (for now). I haven't tested it in any other distro yet.

What? You'd like to have a fancy, no-brainer one-liner to try it quick? You've got it! This will download `enumeraga`, put it on `/opt/enumeraga`, make it executable, create a soft link on your path and finally call it with help flag:

    sudo mkdir /opt/enumeraga; sudo curl -L https://github.com/0x5ubt13/enumeraga/releases/download/v0.1.14-beta/enumeraga_v0.1.14-beta -o /opt/enumeraga/enumeraga; sudo chmod +x /opt/enumeraga/enumeraga; sudo ln -s /opt/enumeraga/enumeraga /usr/bin/enumeraga; enumeraga -h

### Executable version, build it yourself

Make sure you have Go installed first! (In Kali, `apt-get update && apt-get install golang`); then:

    git clone https://github.com/0x5ubt13/enumeraga.git
    cd enumeraga
    go build -o enumeraga main.go
    ./enumeraga -h

### Containerised version

    Containerised version coming soon!!!

## Disclaimer

This tool has to run as `root`, and despite my nickname, it's not precisely a subtle tool! Contrarily, it will create a ton of noise. Given its aggressive nature, please ensure you know what you're doing before launching it, and of course double-check you have absolute permission to enumerate your target(s).

## Similar tools out there

I am aware other enumeration tools exist, but this one aims to be very fast and concise. So far by the current testing times, Enumeraga is able to run its core logic in about 20 to 60 seconds per host, depending on the number of ports open.

Enumeraga's bottleneck is clearly identified at the port sweeping phase. Once that's out the way the rest of logic gets triggered almost instantly, grouping up several ports in their respective protocols and targeting protocols for enumeration instead.

If you have new ideas to implement in this tool or have any feedback please reach out!

## The name

Doing a casual search looking for my tool, I found out that the name "autoEnum" was already taken by a tool also written in Bash doing similar things developed years ago, so I decided to give my tool a different name. I thought of this version as the third iteration of the program, being the first one [autoNmap](https://github.com/0x5ubt13/myToolkit/tree/main/autoNmap), and the second one [autoEnum](https://github.com/0x5ubt13/autoenum).

The next name had to be some sort of third iteration. It was quite fun and creative trying to come up with a new name, and after brainstorming several possibilities, I tried Pokémon, but I could not think of cool name for a second "evolution" using "auto" as a prefix. It made sense borrowing from the spell naming convention of the Final Fantasy universe, which also includes a G in the third version of their spells, and so to honour the decision to use Go, and develop the third stage of a script that does automatic enumeration for you, `Enumeraga` was born.

## Quality and Learning-As-You-Go

This is my first serious tool developed in Go. At the time of creating this repo, I have been learning Golang for the best part of the last 2 years, and I have been using it to develop solutions for the [Advent of Code](https://adventofcode.com/).

Although I will try my best to adhere to coding conventions, I am still learning as I code, and any kind of contribution towards quality will always be welcome.

## Wrapped tools currently present

- Braa
- CeWL
- CrackMapExec
- Enum4linux-ng
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
- Nbtscan-unixwiz
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
- WhatWeb
- WafW00f

Besides from the above 29 tools, there are many more included in GNU/Linux doing magic tricks behind the scenes!! (And now Golang's own logic too!)

## Tools yet to implement

- Do you have any other suggestion? Send a PR or a message!

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

- [x] Port all of this to Golang
- [x] Improve the way output is presented to terminal
- [x] Rewrite in modules to enable `go get`
- [x] Add cool GitHub badges
- [x] Work on getting maintainability rate up to A
- [ ] Test thoroughly
- [ ] Release v1.0
- [ ] Containerise
- [ ] Add a flag to pass `vhosts` and functionality to use them
- [ ] Rewrite the `enum4linux-ng` installing function to avoid installing `pip` and dependencies as `root`
- [ ] Link each wrapped tool on README to their official repos
- [ ] Improve README.md to show all protocols the script enumerates
- [ ] Add MOAR enum tools
- [ ] Enumerate all things (legally, please!)

Happy enumeration!
