import os

# Path to the firmware file you are testing
FIRMWARE_PATH = "/Users/srikanth/Desktop/O1/ESP/vuln_iot_device/full_flash.bin"  # Change this if your file has a different name

if not os.path.exists(FIRMWARE_PATH):
    print(f"❌ File not found at {FIRMWARE_PATH}")
    print("Please check your file path or make sure your hardware dump completed successfully.")
else:
    with open(FIRMWARE_PATH, "rb") as f:
        data = f.read()
    
    print(f"📦 File Size: {len(data)} bytes ({len(data) / (1024*1024):.2f} MB)")
    print("=" * 60)
    print(f"📌 Offset 0x000000 (File Start):  {data[0:16].hex().upper()}")
    
    if len(data) > 0x1000:
        print(f"📌 Offset 0x001000 (Bootloader):  {data[0x1000:0x1016].hex().upper()}")
    if len(data) > 0x8000:
        print(f"📌 Offset 0x008000 (Part Table):  {data[0x8000:0x8016].hex().upper()}")
    if len(data) > 0x10000:
        print(f"📌 Offset 0x010000 (App Image):   {data[0x10000:0x10016].hex().upper()}")
    print("=" * 60)