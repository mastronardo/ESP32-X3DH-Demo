import csv
from os import path
import statistics
import RPi.GPIO as GPIO
from ina219 import INA219, DeviceRangeError
from time import sleep
from datetime import datetime

SHUNT_OHMS = 0.1
MAX_EXPECTED_AMPS = 2.0
CSV_FILE = 'measurements.csv'
STOP_PIN = 17

# busnum=1 is specific for Raspberry Pi 4
ina = INA219(SHUNT_OHMS, MAX_EXPECTED_AMPS, busnum=1)
ina.configure(ina.RANGE_16V)

GPIO.setmode(GPIO.BCM)
GPIO.setup(STOP_PIN, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)

volt = ina.voltage()
currents = []
powers = []

def read_and_store():
    print(f"Voltage: {volt:.3f} V")
    try:
        p = ina.power()
        i = p / volt
        
        currents.append(i)
        powers.append(p)
    except DeviceRangeError:
        print("Current overflow")

try:
    # Handle initial state if pin is floating or already high
    if GPIO.input(STOP_PIN) == GPIO.HIGH:
        print(f"Warning: GPIO {STOP_PIN} is HIGH. Waiting for it to go LOW...")
        while GPIO.input(STOP_PIN) == GPIO.HIGH:
            sleep(0.5)
        print("Line is now LOW. Ready for trigger.")

    print(f"Waiting for Signal HIGH on GPIO {STOP_PIN} to start...")

    # Wait for the Start Signal
    while GPIO.input(STOP_PIN) == GPIO.LOW:
        sleep(0.05)
    
    print("\nSignal Received! Recording started...")
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Record loop
    while GPIO.input(STOP_PIN) == GPIO.HIGH:
        read_and_store()
        sleep(0.1)
    print("\nSignal Stopped. Processing data...")
    
    if len(currents) > 0:
        avg_i = statistics.mean(currents)
        avg_p = statistics.mean(powers)
        
        print(f"Average Power: {avg_p:.2f} mW")
        print(f"Calculated Current: {avg_i:.2f} mA")
        print(f"Saving to {CSV_FILE}...")

        file_exists = path.isfile(CSV_FILE)
        
        with open(CSV_FILE, 'a', newline='') as file:
            writer = csv.writer(file)
            if not file_exists:
                writer.writerow(["Voltage (V)", "Avg Current (mA)", "Avg Power (mW)"])
            writer.writerow([f"{volt:.3f}", f"{avg_i:.3f}", f"{avg_p:.3f}"])
            
    else:
        print("No samples collected (Signal was too short).")

except KeyboardInterrupt:
    print("\nStopped by User")
finally:
    GPIO.cleanup()
    print("Done.")