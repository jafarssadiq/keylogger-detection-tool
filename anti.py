import psutil
import os
import time
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from plyer import notification
import socket

# Initialize rich console
console = Console()

# Configuration
SUSPICIOUS_FILES = ["keylog.txt", "server_log.txt", "log.txt", "keystrokes.log"]
SUSPICIOUS_LIBRARIES = ["pynput", "keyboard"]
CHECK_INTERVAL = 5  # Seconds between checks
LOG_FILE = "detection_log.json"
NOTIFY_TIMEOUT = 5000  # Notification timeout in milliseconds

def log_message(message, level="INFO"):
    """Log detection events to a JSON file with timestamps."""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "level": level,
        "message": message
    }
    try:
        with open(LOG_FILE, "a") as f:
            json.dump(log_entry, f)
            f.write("\n")
    except Exception as e:
        console.print(f"[red]Error logging to {LOG_FILE}: {e}[/red]")

def show_notification(title, message):
    """Show a desktop notification."""
    try:
        notification.notify(
            title=title,
            message=message,
            app_name="Keylogger Detector",
            timeout=NOTIFY_TIMEOUT // 1000
        )
    except Exception as e:
        console.print(f"[red]Notification error: {e}[/red]")

def check_processes():
    """Check running processes for suspicious libraries."""
    table = Table(title="Suspicious Processes")
    table.add_column("PID", style="cyan")
    table.add_column("Process Name", style="magenta")
    table.add_column("Library", style="green")
    table.add_column("Action", style="yellow")

    found = False
    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            cmdline = proc.info['cmdline'] or []
            proc_name = proc.info['name'].lower()
            if 'python' in proc_name:
                for lib in SUSPICIOUS_LIBRARIES:
                    if any(lib in arg.lower() for arg in cmdline):
                        found = True
                        message = f"Suspicious process: {proc_name} (PID: {proc.pid}) using {lib}"
                        log_message(message)
                        console.print(f"[yellow]{message}[/yellow]")
                        show_notification("Keylogger Alert", message)
                        table.add_row(str(proc.pid), proc_name, lib, "Prompt to terminate")
                        action = console.input("[bold cyan]Terminate process (PID: {})? (y/n): [/bold cyan]".format(proc.pid))
                        if action.lower() == 'y':
                            psutil.Process(proc.pid).terminate()
                            term_message = f"Terminated process: {proc_name} (PID: {proc.pid})"
                            log_message(term_message)
                            console.print(f"[green]{term_message}[/green]")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if found:
        console.print(table)
    return found

def check_files():
    """Scan for suspicious files in common directories."""
    table = Table(title="Suspicious Files")
    table.add_column("File Path", style="cyan")
    table.add_column("Action", style="yellow")

    found = False
    search_paths = [os.getcwd(), os.path.expanduser("~")]
    for path in search_paths:
        try:
            for root, _, files in os.walk(path):
                for file in files:
                    if file.lower() in SUSPICIOUS_FILES:
                        file_path = os.path.join(root, file)
                        found = True
                        message = f"Suspicious file found: {file_path}"
                        log_message(message)
                        console.print(f"[yellow]{message}[/yellow]")
                        show_notification("Keylogger Alert", message)
                        table.add_row(file_path, "Prompt to delete")
                        action = console.input("[bold cyan]Delete file {}? (y/n): [/bold cyan]".format(file_path))
                        if action.lower() == 'y':
                            os.remove(file_path)
                            del_message = f"Deleted file: {file_path}"
                            log_message(del_message)
                            console.print(f"[green]{del_message}[/green]")
        except Exception as e:
            log_message(f"Error scanning path {path}: {e}", level="ERROR")
            console.print(f"[red]Error scanning path {path}: {e}[/red]")

    if found:
        console.print(table)
    return found

def check_file_activity():
    """Monitor for recent modifications to potential log files."""
    table = Table(title="Recent File Activity")
    table.add_column("File Path", style="cyan")
    table.add_column("Last Modified", style="green")

    found = False
    search_paths = [os.getcwd(), os.path.expanduser("~")]
    for path in search_paths:
        try:
            for root, _, files in os.walk(path):
                for file in files:
                    if file.lower().endswith('.txt') or file.lower().endswith('.log'):
                        file_path = os.path.join(root, file)
                        try:
                            mtime = os.path.getmtime(file_path)
                            if time.time() - mtime < 60:
                                found = True
                                last_modified = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                                message = f"Recent file modification: {file_path} at {last_modified}"
                                log_message(message)
                                console.print(f"[yellow]{message}[/yellow]")
                                show_notification("Keylogger Alert", message)
                                table.add_row(file_path, last_modified)
                        except Exception:
                            continue
        except Exception as e:
            log_message(f"Error checking file activity in {path}: {e}", level="ERROR")
            console.print(f"[red]Error checking file activity in {path}: {e}[/red]")

    if found:
        console.print(table)
    return found

def check_network():
    """Check for suspicious network connections."""
    table = Table(title="Suspicious Network Connections")
    table.add_column("Local Address", style="cyan")
    table.add_column("Remote Address", style="magenta")
    table.add_column("Status", style="green")

    found = False
    try:
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = f"{conn.raddr.ip}:{conn.raddr.port}"
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                try:
                    hostname = socket.gethostbyaddr(conn.raddr.ip)[0]
                except socket.herror:
                    hostname = "Unknown"
                message = f"Suspicious connection: {local_addr} -> {remote_ip} ({hostname}, {conn.status})"
                log_message(message)
                console.print(f"[yellow]{message}[/yellow]")
                show_notification("Keylogger Alert", message)
                table.add_row(local_addr, f"{remote_ip} ({hostname})", conn.status)
                found = True
    except Exception as e:
        log_message(f"Error checking network: {e}", level="ERROR")
        console.print(f"[red]Error checking network: {e}[/red]")

    if found:
        console.print(table)
    return found

def main():
    """Run the advanced detection tool."""
    console.print("[bold green]Advanced Keylogger Detection Tool Started[/bold green]")
    console.print("Press Ctrl+C to stop.")
    log_message("Advanced Keylogger Detection Tool Started")

    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=None)
            while True:
                progress.update(task, advance=0, description="[cyan]Scanning...")
                any_detected = False
                any_detected |= check_processes()
                any_detected |= check_files()
                any_detected |= check_file_activity()
                any_detected |= check_network()
                if not any_detected:
                    console.print("[green]No suspicious activity detected.[/green]")
                time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        log_message("Detection tool stopped")
        console.print("[bold red]Detection tool stopped.[/bold red]")

if __name__ == "__main__":
    main()