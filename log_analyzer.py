from collections import Counter
import csv

LOG_FILE = "security.log"
REPORT_FILE = "security_report.csv"

failed_ips = []
total_failed = 0
total_success = 0

# Read security log
with open(LOG_FILE, "r") as file:
    for line in file:

        if "LOGIN_FAILED" in line:
            total_failed += 1

            parts = line.split("ip=")

            if len(parts) > 1:
                ip = parts[1].strip()
                failed_ips.append(ip)

        elif "LOGIN_SUCCESS" in line:
            total_success += 1


# Count failed attempts
ip_counts = Counter(failed_ips)

print("=" * 50)
print("             SECURITY LOG ANALYZER")
print("=" * 50)

print("\nSECURITY SUMMARY")
print("-" * 50)

print(f"Total successful logins : {total_success}")
print(f"Total failed logins     : {total_failed}")
print(f"Unique suspicious IPs   : {len(ip_counts)}")


print("\nFAILED LOGIN DETAILS")
print("-" * 50)

for ip, count in ip_counts.items():
    print(f"{ip} -> {count} failed attempts")


print("\nRISK ANALYSIS")
print("-" * 50)

report_data = []
high_risk_count = 0

for ip, count in ip_counts.items():

    if count >= 5:
        risk = "HIGH"
        high_risk_count += 1

    elif count >= 3:
        risk = "MEDIUM"

    else:
        risk = "LOW"

    print(f"{ip} -> {risk} RISK ({count} attempts)")

    report_data.append([ip, count, risk])


# Create CSV report
with open(REPORT_FILE, "w", newline="") as file:

    writer = csv.writer(file)

    writer.writerow(["IP Address", "Failed Attempts", "Risk Level"])

    writer.writerows(report_data)


print("\nFINAL REPORT")
print("-" * 50)

print(f"High-risk IPs detected : {high_risk_count}")

if high_risk_count > 0:
    print("WARNING: Repeated failed login activity detected!")
else:
    print("No high-risk activity detected.")

print(f"\nCSV report created: {REPORT_FILE}")

print("\nAnalysis completed successfully.")
print("=" * 50)
