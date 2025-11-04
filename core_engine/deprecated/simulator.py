def get_test_packet_batch():
    return [
        {
            "program": "net_tool",
            "pid": 1234,
            "port": 8080,
            "payload": "GET /index.html HTTP/1.1\r\nHost: example.com",
            "flags": "S",
        },
        {
            "program": "db_tool",
            "pid": 5678,
            "port": 3307,
            "payload": "mysql_native_password=abcd",
            "flags": "",
        },
        {
            "program": "hacker",
            "pid": 8888,
            "port": 4444,
            "payload": "SSH-2.0-OpenSSH_7.4",
            "flags": "S",
        }
    ]
