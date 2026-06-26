import pandas as pd

class SimpleSIEM:
    def __init__(self):
        self. Firewall_Log = ["2026-08-01 12:00:01 ALLOW 192.168.1.5 8.8.8.8 TCP 443",
                             "2026-08-01 12:00:15 DENY 192.168.1.10 45.23.11.7 TCP 22",
                             "2026-08-01 12:01:03 DENY 192.168.1.10 45.23.11.7 TCP 22",
                             "2026-08-01 12:01:12 DENY 192.168.1.10 45.23.11.7 TCP 22 "]
        rows = [line.split() for line in self.Firewall_Log]

        # Get events
        self.Events  = pd.DataFrame(
            rows,
            columns=['Date', 'Time', 'Action', 'Src_IP', 'Dst_IP', 'PROTOCOL', 'Port']
        )

        
    def Analyze_logs(self):
        events = self.Events

        # Get a denied list and a list of possible SSH attemps
        denied = events[events['Action'] == 'DENY']
        ssh = events[(events['Action'] == 'DENY') & (events['Port'] == '22')]['Src_IP'].value_counts()

        print("ALL EVENTS: ", events, '\n')
        print("DENIEDs: ", denied, '\n')

        # Gets denied IPs
        denied_cnt_alerts = denied['Src_IP'].value_counts()
        denied_cnt_alerts = denied_cnt_alerts[denied_cnt_alerts > 2]

        # Print out alerts
        for SrcIP, Count in ssh.items():
            print(f"ALERT: ({Count}) SSH activity; IP: {SrcIP}")

        for SrcIP, Count in denied_cnt_alerts.items():
            print(f"ALERT: ({Count}) denied access; IP: {SrcIP}")


            

ShtSIEM = SimpleSIEM()
ShtSIEM.Analyze_logs()
