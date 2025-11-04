# core_engine/node_controller.py

import socket
import json
import threading

def start_slave_listener(master_ip, master_port, node_id):
    def send_periodic_status():
        while True:
            message = json.dumps({
                "node_id": node_id,
                "event": "STATUS",
                "payload": {"status": "OK"}
            })
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((master_ip, master_port))
                sock.sendall(message.encode())
            except Exception as e:
                print(f"Slave {node_id} failed to reach master: {e}")
            finally:
                sock.close()
            time.sleep(10)

    thread = threading.Thread(target=send_periodic_status, daemon=True)
    thread.start()

def start_master_listener(bind_port):
    def handle_connection(conn, addr):
        data = conn.recv(4096)
        try:
            msg = json.loads(data.decode())
            print(f"[MASTER] Received from {msg['node_id']}: {msg['event']} - {msg['payload']}")
        except Exception as e:
            print(f"[MASTER] Invalid message: {e}")
        conn.close()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(('', bind_port))
    server_sock.listen(5)
    print(f"[MASTER] Listening on port {bind_port}...")

    while True:
        conn, addr = server_sock.accept()
        threading.Thread(target=handle_connection, args=(conn, addr)).start()

