from Configs import *
import pandas as pd

class SimpleSIEM:
    def __init__(self):
        self.Firewall_Log = [
            # Normal traffic
            "2026-08-01 12:00:01 ALLOW 192.168.1.5 8.8.8.8 TCP 443",
            "2026-08-01 12:00:08 ALLOW 192.168.1.8 1.1.1.1 TCP 443",
            "2026-08-01 12:00:15 ALLOW 192.168.1.20 172.217.14.206 TCP 80",
            "2026-08-01 12:00:22 ALLOW 192.168.1.7 8.8.4.4 UDP 53",
            "2026-08-01 12:00:31 ALLOW 192.168.1.15 151.101.1.69 TCP 443",
            "2026-08-01 12:00:39 ALLOW 192.168.1.3 104.18.24.1 TCP 443",

            # SSH attempts
            "2026-08-01 12:01:01 DENY 45.23.11.7 192.168.1.10 TCP 22",
            "2026-08-01 12:01:04 DENY 45.23.11.7 192.168.1.10 TCP 22",
            "2026-08-01 12:01:07 DENY 45.23.11.7 192.168.1.10 TCP 22",
            "2026-08-01 12:01:10 DENY 45.23.11.7 192.168.1.10 TCP 22",
            "2026-08-01 12:01:13 DENY 45.23.11.7 192.168.1.10 TCP 22",
            "2026-08-01 12:01:16 DENY 45.23.11.7 192.168.1.10 TCP 22",

            # Port scan
            "2026-08-01 12:02:01 DENY 91.201.45.88 192.168.1.20 TCP 21",
            "2026-08-01 12:02:03 DENY 91.201.45.88 192.168.1.20 TCP 22",
            "2026-08-01 12:02:05 DENY 91.201.45.88 192.168.1.20 TCP 23",
            "2026-08-01 12:02:07 DENY 91.201.45.88 192.168.1.20 TCP 25",
            "2026-08-01 12:02:09 DENY 91.201.45.88 192.168.1.20 TCP 53",
            "2026-08-01 12:02:11 DENY 91.201.45.88 192.168.1.20 TCP 80",
            "2026-08-01 12:02:13 DENY 91.201.45.88 192.168.1.20 TCP 110",
            "2026-08-01 12:02:15 DENY 91.201.45.88 192.168.1.20 TCP 143",
            "2026-08-01 12:02:17 DENY 91.201.45.88 192.168.1.20 TCP 443",

            # Random denied traffic
            "2026-08-01 12:03:01 DENY 102.44.1.18 192.168.1.7 TCP 3389",
            "2026-08-01 12:03:08 DENY 200.17.88.9 192.168.1.12 UDP 161",
            "2026-08-01 12:03:15 DENY 150.88.42.77 192.168.1.8 TCP 445",

            # Mixed normal traffic
            "2026-08-01 12:04:01 ALLOW 192.168.1.21 8.8.8.8 UDP 53",
            "2026-08-01 12:04:12 ALLOW 192.168.1.30 104.16.132.229 TCP 443",
            "2026-08-01 12:04:25 ALLOW 192.168.1.18 172.217.14.206 TCP 80",

            # Another suspicious host
            "2026-08-01 12:05:01 DENY 103.99.77.1 192.168.1.50 TCP 22",
            "2026-08-01 12:05:03 DENY 103.99.77.1 192.168.1.50 TCP 22",
            "2026-08-01 12:05:05 DENY 103.99.77.1 192.168.1.50 TCP 22",
            "2026-08-01 12:05:07 DENY 103.99.77.1 192.168.1.50 TCP 22",
            "2026-08-01 12:05:09 DENY 103.99.77.1 192.168.1.50 TCP 22",

            # More normal traffic
            "2026-08-01 12:06:01 ALLOW 192.168.1.6 8.8.8.8 TCP 443",
            "2026-08-01 12:06:10 ALLOW 192.168.1.14 1.0.0.1 UDP 53",
            "2026-08-01 12:06:18 ALLOW 192.168.1.25 52.95.110.1 TCP 443",
        ]

        rows = [line.split() for line in self.Firewall_Log]

        # Get events
        self.events  = pd.DataFrame(rows, columns=["Date", "Time", "Action", "Src_IP", "Dst_IP", "Protocol", "Port"])
        self.alerts = []
        self.severity = {"CRITICAL" : 0, "HIGH" : 0, "MEDIUM" : 0, "LOW" : 0}


    def analyze_logs(self):
        events = self.events

        self.get_multiple_denials(events)
        self.get_ssh_attemps(events)
        self.get_port_scan(events)
        self.get_SSH_brute(events)

        # Print out events and denied events
        #print("ALL events: ", events, "\n")
        
        print("=============================================")
        print("            SIMPLE SIEM DASHBOARD            ") 
        print("=============================================\n")

        alert_count = len(self.alerts)
        print(f"ACTIVE ALERTS: {alert_count}")
        
        for severity, Count in self.severity.items():
            print(f"{severity} : {Count}")

        print("\n=============================================\n")

        # Print out alerts
        for alert in self.alerts:
            print(f"[{alert['severity']}] "
                  f"{alert['type']} | "
                  f"{alert['ip']} | "
                  f"{alert['count']}")
        
    
    # ADD ALERT FUNC
    def add_alert(self, alert_type, ip, Count):
        if   Count >= 50: severity = "CRITICAL"
        elif Count >= 20: severity = "HIGH"
        elif Count >= 5 : severity = "MEDIUM"
        else: severity = "LOW"
        self.severity[severity] += 1

        self.alerts.append({
            "type" : alert_type,
            "severity" : severity,
            "ip" : ip,
            "count" : Count
        })


    # MULTIPLE DENIALS CHECK
    def get_multiple_denials(self, events):
        denied = events[events["Action"] == "DENY"]
        denied_cnt_alerts = denied["Src_IP"].value_counts()
        for SrcIP, Count in denied_cnt_alerts.items():
            if Count >= DENIAL_THRESHOLD:
                self.add_alert("Multiple Denials", SrcIP, Count)


    # SSH ATTEMPS CHECK
    def get_ssh_attemps(self, events):
        ssh_suspects = events[(events["Action"] == "DENY") & (events["Port"] == "22")]["Src_IP"].value_counts()
        for SrcIP, Count in ssh_suspects.items():
            if Count >= SSH_ACTIVITY_THRESHOLD:
                self.add_alert("SSH Activity", SrcIP, Count)


    # PORTS SCAN CHECK
    def get_port_scan(self, events):
        ports_per_IP = events.groupby("Src_IP")["Port"].nunique()
        for SrcIP, Count in ports_per_IP.items():
            if Count >= PORT_SCAN_THRESHOLD:
                self.add_alert("Port Scan", SrcIP, Count)


    # SSH BRUTE CHECK
    def get_SSH_brute(self, events):
        ssh_suspects = events[(events["Action"] == "DENY") & (events["Port"] == "22")]["Src_IP"].value_counts()
        for SrcIP, Count in ssh_suspects.items():
            if Count >= SSH_BRUTE_THRESHOLD:
                self.add_alert("Brute Force", SrcIP, Count)
            

ShtSIEM = SimpleSIEM()
ShtSIEM.analyze_logs()
