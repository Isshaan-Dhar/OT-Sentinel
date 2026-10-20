import asyncio
import logging
from pymodbus.server import StartAsyncTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext

logging.basicConfig(level=logging.ERROR)

async def run_server():
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*100),
        co=ModbusSequentialDataBlock(0, [0]*100),
        hr=ModbusSequentialDataBlock(0, [25, 1013, 1] + [0]*97),
        ir=ModbusSequentialDataBlock(0, [0]*100),
        zero_mode=True
    )
    context = ModbusServerContext(slaves=store, single=True)
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'OT-Sentinel Sim'
    identity.ProductCode = 'OTS-01'
    identity.MajorMinorRevision = '1.0.0'
    print("Starting Virtual Modbus PLC on port 502...", flush=True)
    await StartAsyncTcpServer(context=context, identity=identity, address=("0.0.0.0", 502))

if __name__ == "__main__":
    asyncio.run(run_server())