import os
import time
import hashlib
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ==========================================
# CONFIGURATION & PROFESSIONAL LOGGING SETUP
# ==========================================

# We use the logging module instead of print() to create an actual audit trail file.
LOG_FILE = "security_audit.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler() # This also prints to the VS Code terminal
    ]
)

# Define directories to monitor and classify
WATCH_DIR = "."  # Watches the current directory and all subdirectories
SENSITIVE_DIRS = ["sensitive_data"] 
SUSPICIOUS_DESTINATIONS = ["usb_simulation"]

# ==========================================
# CORE LOGIC: FILE HASHING & EVENT HANDLING
# ==========================================

def calculate_sha256(filepath):
    """Calculates the SHA-256 hash of a file for integrity checking."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Hash Error: {e}"

class SecurityMonitorHandler(FileSystemEventHandler):
    """Handles file system events and applies security rules."""

    def is_sensitive(self, filepath):
        """Checks if the file belongs to a restricted directory."""
        for d in SENSITIVE_DIRS:
            if d in filepath:
                return True
        return False

    def on_created(self, event):
        if event.is_directory:
            return
        
        file_hash = calculate_sha256(event.src_path)
        logging.info(f"FILE CREATED/UPLOADED: {event.src_path} | SHA256: {file_hash}")

    def on_deleted(self, event):
        if event.is_directory:
            return
        
        if self.is_sensitive(event.src_path):
            logging.warning(f"ALERT (DELETION): Sensitive file deleted! Path: {event.src_path}")
        else:
            logging.info(f"FILE DELETED: {event.src_path}")

    def on_modified(self, event):
        if event.is_directory: return
        
        # --- NEW CODE: IGNORE THE LOG FILE TO PREVENT INFINITE LOOPS ---
        if "security_audit.log" in event.src_path:
            return
        

        file_hash = calculate_sha256(event.src_path)
        
        # Threat Check: Was a protected file tampered with?
        if self.is_sensitive(event.src_path):
            logging.warning(f"INTEGRITY ALERT (Tampering): {event.src_path} | New Hash: {file_hash}")
        else:
            logging.info(f"FILE MODIFIED: {event.src_path} | New Hash: {file_hash}")

    def on_moved(self, event):
        if event.is_directory:
            return

        # Check for unauthorized exfiltration (e.g., moving to a USB)
        for suspicious_dir in SUSPICIOUS_DESTINATIONS:
            if suspicious_dir in event.dest_path and self.is_sensitive(event.src_path):
                logging.error(f"CRITICAL ALERT: Data Exfiltration Attempt! Sensitive file moved to {suspicious_dir}. Src: {event.src_path} -> Dest: {event.dest_path}")
                return

        logging.info(f"FILE MOVED: {event.src_path} -> {event.dest_path}")


# SYSTEM EXECUTION


if __name__ == "__main__":
    logging.info("Starting Secure File Transfer Monitoring System...")
    logging.info(f"Monitoring Directory: {os.path.abspath(WATCH_DIR)}")
    
    event_handler = SecurityMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    
    observer.start()
    try:
        while True:
            time.sleep(1) # Keeps the script running continuously
    except KeyboardInterrupt:
        logging.info("System shutting down. Stopping monitor...")
        observer.stop()
    observer.join()
