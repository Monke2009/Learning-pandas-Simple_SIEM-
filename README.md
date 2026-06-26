My first project, experimenting with pandas

# Simple ideas:
The SIEM class includes:
- a firewall log
- a map of events
- a map of denied IPs

# How it works:
**CATEGORIZING**
- The event map reads from the firewall log and splits it into separate events
- During the process, if a log was marked "DENY", the denied IP would be stored in the denied IPs map
- The denied IPs map stores denied IPs and how many times an IP was denied access
**ANALYZING**
- When analyzing, the program starts by looking at the denied IPs list
- If an IP was denied more than the preset limit (3 times), the SIEM would print out an alert and name the IP
- Next, the program looks at the events map, and if an IP used port 22, the SIEM would print out an SSH activity alert and name out the IP


Please leave some feedback if you don't mind, I'm trying to improve
