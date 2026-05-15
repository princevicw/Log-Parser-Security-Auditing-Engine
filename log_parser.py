import re
import json
from collections import defaultdict
from datetime import datetime, timedelta

# Configuration
LOG_FILE = "server.log"  # Path to the log file
BRUTE_FORCE_THRESHOLD = 5  # Number of 401 errors from the same IP within a time window
TRAFFIC_SPIKE_THRESHOLD = 100  # Number of requests within a time window
TIME_WINDOW = timedelta(minutes=1)  # Time window for anomaly detection

def stream_logs(file_path):
    """Stream logs line by line."""
    with open(file_path, "r") as file:
        for line in file:
            yield line.strip()

def parse_log_line(line):
    """Parse a log line into structured data."""
    log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<url>[^\s]+) HTTP/\d\.\d" (?P<status>\d+) (?P<size>\d+)'
    match = re.match(log_pattern, line)
    if match:
        return match.groupdict()
    return None

def detect_anomalies(log_entries):
    """Detect anomalies in the log entries."""
    brute_force_attempts = defaultdict(list)
    traffic_counts = defaultdict(int)
    anomalies = []

    for entry in log_entries:
        ip = entry['ip']
        status = int(entry['status'])
        timestamp = datetime.strptime(entry['timestamp'], "%d/%b/%Y:%H:%M:%S %z")

        # Detect brute-force login attempts
        if status == 401:
            brute_force_attempts[ip].append(timestamp)
            brute_force_attempts[ip] = [t for t in brute_force_attempts[ip] if t > timestamp - TIME_WINDOW]
            if len(brute_force_attempts[ip]) >= BRUTE_FORCE_THRESHOLD:
                anomalies.append({"type": "brute_force", "ip": ip, "count": len(brute_force_attempts[ip])})

        # Detect traffic spikes
        traffic_counts[timestamp] += 1
        if traffic_counts[timestamp] >= TRAFFIC_SPIKE_THRESHOLD:
            anomalies.append({"type": "traffic_spike", "timestamp": timestamp.isoformat(), "count": traffic_counts[timestamp]})

    return anomalies

def main():
    log_entries = (parse_log_line(line) for line in stream_logs(LOG_FILE))
    log_entries = filter(None, log_entries)  # Remove None entries
    anomalies = detect_anomalies(log_entries)

    # Output anomalies as JSON
    with open("anomalies.json", "w") as output_file:
        json.dump(anomalies, output_file, indent=4)
    print("Anomalies detected and saved to anomalies.json")

if __name__ == "__main__":
    main()
