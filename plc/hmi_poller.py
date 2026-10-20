import time
from pymodbus.client import ModbusTcpClient

def run_poller():
    client = ModbusTcpClient('host.docker.internal', port=5020)
    while True:
        if client.connect():
            result = client.read_holding_registers(0, 3, slave=1)
            if not result.isError():
                print(f"HMI Polled State -> Temp: {result.registers[0]}C, Pressure: {result.registers[1]}hPa, Valve: {result.registers[2]}", flush=True)
        time.sleep(0.5)

if __name__ == "__main__":
    time.sleep(3)
    run_poller()