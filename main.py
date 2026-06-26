from Simple_SIEM import SimpleSIEM
import sys

def main():
    siem = SimpleSIEM()
    siem.analyze_logs()


if __name__ == "__main__":
    main()
    sys.exit()