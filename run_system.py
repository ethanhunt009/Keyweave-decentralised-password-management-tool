import os
import subprocess
import signal
import time
import config
from multiprocessing import Process

processes = []

def start_vault():
    print("Starting Vault Coordinator...")
    os.chdir("vault")
    proc = subprocess.Popen(["python", "server.py"])
    processes.append(proc)
    os.chdir("..")
    time.sleep(2)

def start_guardian(port):
    print(f"Starting Guardian on port {port}...")
    env = os.environ.copy()
    env["GUARDIAN_PORT"] = str(port)
    proc = subprocess.Popen(["python", "guardian/node.py"], env=env)
    processes.append(proc)
    time.sleep(0.5)

def start_client():
    print("Starting Client Application...")
    proc = subprocess.Popen(["python", "client/app.py"])
    processes.append(proc)

def run_tests():
    print("Running Research Validation Tests...")
    os.chdir("tests")
    subprocess.run(["python", "security_audit.py"])
    subprocess.run(["python", "performance_test.py"])
    subprocess.run(["python", "recovery_scenarios.py"])
    os.chdir("..")

def cleanup(signum, frame):
    print("\nTerminating processes...")
    for p in processes:
        p.terminate()
    exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup)
    
    # Start components
    start_vault()
    
    for port in config.Config.GUARDIAN_PORTS:
        start_guardian(port)
    
    # Wait for servers to initialize
    time.sleep(3)
    
    # Start client or run tests
    if input("Run tests? (y/n): ").lower() == "y":
        run_tests()
    else:
        start_client()
    
    # Keep running until interrupted
    while True:
        time.sleep(1)