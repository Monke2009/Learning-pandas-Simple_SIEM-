My first project, experimenting with pandas

# Simple ideas:
The SIEM class includes:
- a firewall log
- a map of events
- a map of denied IPs

# How it works:
**CATEGORIZING**
- The event map reads from the firewall log and splits it into separate events
- During the process, if a log were marked "DENY", the denied IP would be stored in the denied IPs map
- The denied IPs map stores denied IPs and how many times an IP was denied access
**ANALYZING**
- Detects and saves threats to a list for later display
- Print alerts from the list

**Update 0.1:**
- Removed global threat lists
- Added alert list (Alerts are now printed from the alert list)
- Added helper function "add_alerts"
- Added severity categorizing
- Separated threat categorization into functions
- Added (Port scan, SSH brute)

Please leave some feedback if you don't mind. I'm trying to improve
