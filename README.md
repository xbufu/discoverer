# Discoverer

Discoverer is a tool I wrote while preparing for the eCPTP certification by eLearnSecurity. It follows the recon methodology described in the course. It currently runs:

1. Host discovery using `nmap`
2. OS discovery using `nmap`
3. TCP port scan using TheMayor's code from his [Threader3000](https://github.com/dievus/threader3000) project
4. UDP scan of top 25 ports using `nmap`
5. Service detection using `nmap`

As mentioned above, I shamelessly stole TheMayor's code for the TCP port scan, since nmap was just too slow. I hope he doesn't mind ;)