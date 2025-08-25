import socket
import threading
import random
import time
import os

def simulate_safe_service(port=8080):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', port))
    server.listen(5)
    print(f"[SAFE] Simulated HTTP server listening on port {port}")

    while True:
        try:
            client_socket, addr = server.accept()
            client_socket.send(b"Hello from safe server\n")
            client_socket.close()
        except:
            break

def simulate_suspicious_connection(remote_host="8.8.8.8", remote_port=9999):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remote_host, remote_port))
        print(f"[SUSPICIOUS] Connected to {remote_host}:{remote_port}")
        time.sleep(2)
        s.close()
    except Exception as e:
        print(f"[SUSPICIOUS ERROR] {e}")

def run_simulation():
    print("🔁 Starting traffic simulation...")

    # Safe HTTP service
    t1 = threading.Thread(target=simulate_safe_service, args=(8080,))
    t1.daemon = True
    t1.start()

    # Repeated suspicious connections
    for _ in range(5):
        simulate_suspicious_connection("93.184.216.34", random.randint(40000, 60000))  # example.com
        time.sleep(random.uniform(1, 3))

    print("🧪 Simulation complete. You can now run the port scanner to capture this activity.")

if __name__ == "__main__":
    run_simulation()

