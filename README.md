# Secure-File-Transfer-Monitoring-System
Organizations face constant threats involving unauthorized file transfers, data theft, and malicious file tampering. This project presents a Secure File Transfer Monitoring System designed to act as a real-time Data Loss Prevention (DLP) and File Integrity Monitoring (FIM) engine. Built using Python, the system monitors a live directory environment to detect suspicious file movements, verify file integrity via SHA-256 hashing, and log all events to a secure audit trail.
2. Project Objectives
1.	File System Monitoring: Continuously track file creation, modification, deletion, and movement.
2.	Integrity Verification: Calculate pre- and post-transfer SHA-256 hashes to detect unauthorized tampering.
3.	Data Exfiltration Prevention: Alert when sensitive files are moved to unauthorized destinations (e.g., simulated USB drives).
4.	Audit Logging: Generate a permanent, professional security log for incident response.
3. Architecture & Methodology
3.1 Technology Stack
•	Language: Python 3
•	Libraries: watchdog (real-time filesystem event monitoring), hashlib (SHA-256 cryptography), logging (audit trails).
•	Environment: Visual Studio Code (VS Code) with an isolated Virtual Environment (venv).
3.2 System Flow
 
The system categorizes events into three specific threat levels based on directory rules:
•	INFO (Normal): Safe file creation or movement outside of protected directories.
•	WARNING (Integrity Alert): A file within a protected directory is modified, changing its cryptographic hash.
•	CRITICAL (Exfiltration Alert): A file from a protected directory is moved to an unauthorized external destination.
4. Threat Simulation & Testing
To validate the system, three real-world threat scenarios were simulated in a controlled environment containing a sensitive_data directory and a usb_drive simulation directory.
4.1 Standard Operations (Baseline)
A standard text file (test.txt) was created in an unprotected directory. The system successfully calculated the baseline hash and logged the event without raising false alarms.

4.2 File Tampering (Ransomware/Insider Modification)
A protected file (passwords.txt) within the sensitive_data directory was intentionally modified. The system detected the change, recalculated the hash, and triggered an Integrity Alert to warn of unauthorized tampering.

4.3 Data Exfiltration (Insider Threat)
To simulate data theft, the protected passwords.txt file was dragged into the usb_drive directory. The system recognized the source-to-destination violation and instantly triggered a Critical Alert.

5. Challenges Overcome: The Infinite Log Loop
During the initial testing phase, a recursion bug was discovered. Because the watchdog script monitors all file modifications in the directory, every time the script wrote an event to security_audit.log, the watchdog detected the log file being modified and recorded that event, triggering an infinite logging loop.
To solve this, custom filtering logic was implemented within the on_modified event handler:
Python
if "security_audit.log" in event.src_path:
    return
This successfully instructed the engine to ignore its own output file, stabilizing the system and ensuring clean, accurate alerts.
6. Conclusion & Security Audit Log
All filesystem events were successfully recorded in an immutable text file to ensure compliance and assist in post-incident investigations.
 
This project demonstrates that robust Data Loss Prevention requires context-aware monitoring. By combining real-time filesystem tracking with cryptographic hashing, organizations can effectively detect and respond to insider threats and data tampering the exact moment they occur.

