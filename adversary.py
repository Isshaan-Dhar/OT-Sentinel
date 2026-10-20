from pymodbus.client import ModbusTcpClient

def inject_anomaly():
    client = ModbusTcpClient('127.0.0.1', port=5020)
    if client.connect():
        print("Injecting MITRE T0855: Unauthorized Command Message (Func 0x06)...")
        client.write_register(1, 9999, slave=1)
        client.close()

if __name__ == "__main__":
    inject_anomaly()