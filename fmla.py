from pathlib import Path


class LogAnalyzer:

    def __init__(self):

        self.rLog = []
        self.alerts = []

        self.ipCount = {}
        self.eventCount = {}

        self.rawEvents = {
            "failed-passwords": [],
            "sudo-events": [],
            "root-logins": [],
            "invalid-users": []
        }

        self.hourCount = {}

        self.usernameCount = {}

        self.failedPasswordCount = 0
        self.invalidUserCount = 0
        self.failedLoginCount = 0

    # -----------------------
    # HELPERS
    # -----------------------

    def ip_finder(self, parts):

        if "from" in parts:

            position = parts.index("from") + 1

            if position < len(parts):

                return parts[position]

        return None

    def username_finder(self, parts):

        if "for" in parts:

            position = parts.index("for") + 1

            if position < len(parts):

                return parts[position]

        return None

    def timestamp_finder(self, parts):

        if len(parts) >= 3:

            return parts[2]

        return "unknown"

    def hour_finder(self, timestamp):

        if ":" in timestamp:

            return timestamp.split(":")[0]

        return "unknown"

    def add_alert(self, alert_type, ip, count, raw):

        self.alerts.append({
            "type": alert_type,
            "ip": ip,
            "count": count,
            "raw": raw
        })

    def increase_count(self, name, counter_dict):

        counter_dict[name] = counter_dict.get(name, 0) + 1

        return counter_dict[name]

    # -----------------------
    # FILE LOADING
    # -----------------------

    def load_log(self, log_path):

        try:

            with open(log_path, "r", encoding="utf-8", errors="ignore") as file:

                self.rLog = file.readlines()

            print(f"\n[+] Loaded {len(self.rLog)} log lines")

        except FileNotFoundError:

            print(f"\n[-] {log_path} not found")

        except PermissionError:

            print(f"\n[-] Permission denied for {log_path}")
            print("[!] Try running with sudo")

    # -----------------------
    # DETECTION METHODS
    # -----------------------

    def detect_failed_passwords(self, line, parts, raw):

        if "failed password" in line:

            self.failedPasswordCount += 1
            self.rawEvents["failed-passwords"].append(raw.strip())

            ip = self.ip_finder(parts)
            user = self.username_finder(parts)

            timestamp = self.timestamp_finder(parts)
            hour = self.hour_finder(timestamp)

            self.increase_count(hour, self.hourCount)

            if user is not None:

                self.increase_count(user, self.usernameCount)

            if ip is not None:

                currentCount = self.increase_count(ip, self.ipCount)

                if currentCount > 5:

                    self.add_alert(
                        "brute-force",
                        ip,
                        currentCount,
                        raw.strip()
                    )

    def detect_invalid_users(self, line, parts, raw):

        if "invalid user" in line:

            self.invalidUserCount += 1
            self.rawEvents["invalid-users"].append(raw.strip())

            ip = self.ip_finder(parts)
            user = self.username_finder(parts)

            if user is not None:

                self.increase_count(user, self.usernameCount)

            if ip is not None:

                currentCount = self.increase_count(ip, self.ipCount)

                if currentCount > 10:

                    self.add_alert(
                        "invalid-user-scanning",
                        ip,
                        currentCount,
                        raw.strip()
                    )

    def detect_failed_logins(self, line):

        if "failed login" in line:

            self.failedLoginCount += 1

    def detect_sudo(self, line, raw, parts):

        if "sudo" in line:

            sudoCount = self.increase_count("sudo", self.eventCount)

            user = self.username_finder(parts)

            if user is not None:

                self.increase_count(user, self.usernameCount)

            self.rawEvents["sudo-events"].append(raw.strip())

            self.add_alert(
                "sudo-event",
                None,
                sudoCount,
                raw.strip()
            )

    def detect_root_login(self, line, raw, parts):

        if "root login" in line or "session opened for user root" in line:

            rootCount = self.increase_count("root-login", self.eventCount)

            user = self.username_finder(parts)

            if user is not None:

                self.increase_count(user, self.usernameCount)

            self.rawEvents["root-logins"].append(raw.strip())

            self.add_alert(
                "root-login",
                None,
                rootCount,
                raw.strip()
            )

    # -----------------------
    # MAIN ANALYSIS
    # -----------------------

    def analyze(self):

        for raw in self.rLog:

            line = raw.lower()
            parts = raw.split()

            self.detect_failed_passwords(line, parts, raw)
            self.detect_invalid_users(line, parts, raw)
            self.detect_failed_logins(line)
            self.detect_sudo(line, raw, parts)
            self.detect_root_login(line, raw, parts)

    # -----------------------
    # SUMMARY
    # -----------------------

    def create_summary(self):

        summary = []

        summary.append("\n========== SUMMARY ==========\n")

        summary.append(f"Failed passwords : {self.failedPasswordCount}")
        summary.append(f"Invalid users    : {self.invalidUserCount}")
        summary.append(f"Failed logins    : {self.failedLoginCount}")

        summary.append("\n========== TOP IPS ==========\n")

        for ip, count in sorted(
            self.ipCount.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            summary.append(f"{ip} -> {count}")

        summary.append("\n========== TOP USERS ==========\n")

        for user, count in sorted(
            self.usernameCount.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            summary.append(f"{user} -> {count}")

        summary.append("\n========== HOURLY ACTIVITY ==========\n")

        for hour, count in sorted(
            self.hourCount.items(),
            key=lambda x: x[0]
        ):
            summary.append(f"{hour}:00 -> {count}")

        summary.append("\n========== ALERTS ==========\n")

        if len(self.alerts) == 0:
            summary.append("No alerts detected")
        else:
            for alert in self.alerts:
                summary.append(
                    f"[!] {alert['type']} | IP: {alert['ip']} | Count: {alert['count']} | RAW: {alert['raw']}"
                )

        summary.append("\n========== RAW FAILED PASSWORDS ==========\n")

        for raw in self.rawEvents["failed-passwords"][:20]:
            summary.append(raw)

        summary.append("\n========== RAW SUDO EVENTS ==========\n")

        for raw in self.rawEvents["sudo-events"][:20]:
            summary.append(raw)

        summary.append("\n========== RAW ROOT LOGINS ==========\n")

        for raw in self.rawEvents["root-logins"][:20]:
            summary.append(raw)

        return "\n".join(summary)

    # -----------------------
    # SAVE OUTPUT
    # -----------------------

    def save_output(self, output_text, file_name):

        output_dir = Path("outputs")
        output_dir.mkdir(exist_ok=True)

        if not file_name.endswith(".txt"):
            file_name += ".txt"

        output_path = output_dir / file_name

        with open(output_path, "w", encoding="utf-8") as file:
            file.write(output_text)

        return output_path


print(r"""

╔══════════════════════════════════════════════╗
║                                              ║
║        Fedora MultiLog Threat Analyzer       ║
║                                              ║
║        SSH • SUDO • ROOT • BRUTEFORCE        ║
║                                              ║
║              CREATED BY KHABOOT              ║
╚══════════════════════════════════════════════╝

""")

print("""
================ LOG SOURCES =================

[1] Fedora Secure Log (/var/log/secure)
[2] Fedora System Messages (/var/log/messages)
[3] Fedora Boot Log (/var/log/boot.log)
[4] Fedora DNF Log (/var/log/dnf.log)
[5] Custom Log Path

==============================================
""")

choice = input("Select log source: ")

if choice == "1":
    log = "/var/log/secure"
elif choice == "2":
    log = "/var/log/messages"
elif choice == "3":
    log = "/var/log/boot.log"
elif choice == "4":
    log = "/var/log/dnf.log"
elif choice == "5":
    log = input("\nEnter full log path: ")
else:
    print("\n[-] Invalid option")
    exit()

if not Path(log).exists():
    print(f"\n[-] File does not exist: {log}")
    exit()

analyzer = LogAnalyzer()
analyzer.load_log(log)

if len(analyzer.rLog) == 0:
    print("\n[-] Log file is empty")
    exit()

analyzer.analyze()

summary = analyzer.create_summary()

print(summary)

save = input("\nSave report? (Y/N): ").lower()

if save == "y":

    file_name = input("Report file name: ")

    path = analyzer.save_output(summary, file_name)

    print(f"\n[+] Report saved to: {path}")
