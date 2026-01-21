# X3DH implementation for ESP32
A demo with native C implementation of X3DH Key Agreement Protocol for ESP32. The project consists of a `Server`, `VPN Server`, and `Clients`. The `Server` is built using Python and Flask framework, and it runs inside a Docker container. The `VPN Server` is built using WireGuard and it also runs inside a Docker container. The `Client` is built using ESP-IDF framework and runs on an ESP32 microcontroller. The `Clients` connect to the `Server` via the `VPN Server` to securely perform the X3DH Key Agreement Protocol. HTTP is used for the communication between the `Clients` and the `Server`.

## Specifications
`Host`'s specifications:
- OS: macOS 26.2
- Architecture: arm64
- CPU : Apple M2 (8)
- RAM : 8 GB
- Command Line Tools for Xcode: 26.2
- Python: 3.12.10 (at least 3.9)
- clang: 17.0.0
- cmake: 4.2.1 (at least 3.16)
- ninja: 1.13.2
- ccache: 4.12.2
- git: 2.52.0
- dfu-util: 0.11
- Docker Desktop: 4.57.0
  - Engine: 29.1.3
  - Compose: 5.0.1

`Server`'s specifications:
- OS: Alpine Linux 3.23.2
- Python: 3.14.2
- Flask: 3.1.2
- SQLite: 3.51.1

`VPN Server`'s specifications:
- OS: Alpine Linux 3.23.2
- WireGuard: 1.0.20250521

`ESP32`'s specifications:
- MCU module: ESP32-WROOM-32E
- Chip: ESP32-D0WD-V3 (revision v3.0)
- ESP-IDF: 5.5.1 (at least 5.3.0)
- gcc: 14.2.0
- cjson: 1.7.19
- libsodium: 1.0.20
- libxeddsa: 2.0.1
- MbedTLS: 3.6.4
- esp_wireguard: 0.9.0

## macOS issues

If you are using `macOS`: 
1. make sure to update the Python certificates. To make it easier, I strongly suggest to download Python from the official website, instead of using HomeBrew/MacPorts, and then run the following commands in your terminal:

```bash
cd /Applications/Python\ 3.x/
./Install\ Certificates.command
```

2. if you cannot see the ESP32 serial port after connecting it via USB, you might need to install the appropriate drivers. You could try to install the [WCH34 driver](https://www.wch-ic.com/downloads/CH34XSER_MAC_ZIP.html) and follow the installation guide from the official [repository](https://github.com/WCHSoftGroup/ch34xser_macos), or you could try to install the [Silicon Labs CP210x driver](https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers).

# How to build it

```bash
git clone https://github.com/mastronardo/ESP32-X3DH-Demo.git
cd ESP32-X3DH-Demo
chmod +x start_service.sh stop_service.sh down_service.sh update_wg_config.sh
```

## Client
The first step is to set up the ESP-IDF environment. You can follow the official guide [here](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html).

### Component Registry
Now you can add the need components via ESP Component Registry. You can simply run the following commands to add the required dependencies for this project:

```bash
pip install -U pip # be sure to have the latest pip version
pip install -U idf-component-manager # be sure to keep the component Manager updated

idf.py add-dependency "espressif/libsodium^1.0.20~3"
idf.py add-dependency "espressif/cjson^1.7.19"
idf.py add-dependency "trombik/esp_wireguard^0.9.0"
```

The most difficult regards the building of [libxeddsa](https://github.com/Syndace/libxeddsa) library for ESP-IDF, since it is not available in the Component Registry. The first step was to clone the repository inside the `components` directory.

```bash
mkdir -p client/components && cd client/components
git clone https://github.com/Syndace/libxeddsa.git
```

After that, the following files inside the `libxeddsa` directory were been modified to make the library compatible with ESP-IDF: `CMakeLists.txt`, `ref10/CMakeLists.txt`, `ref10/include/cross_platform.h`. In addition, some files that were not needed for this project (for example _tests_ and _docs_), were deleted to free some space in the flash memory.

### sdkconfig
`sdkconfig.defaults` was created to automatically generate the `sdkconfig` file when you open the `menuconfig` or set the target.
1. To make sure that the client binary executable file will fit inside the flash memory of the ESP32, and to avoid stack overflow issue when running the project, these parameters were set:
  - `(Top)` ---> `Partition Table` ---> `Partition Table` ---> `Two large size OTA partitions`
  - `(Top)` ---> `Serial Flasher Config` ---> `Flash size` ---> `4MB`
  - `(Top)` ---> `Component config` ---> `ESP System Settings` --> `Main task stack size` ---> `10240`
2. To enable the HKDF algorithm required by the X3DH Key Agreement Protocol:
  - `(Top)` ---> `Component config` ---> `mbedTLS` ---> `HKDF algorithm (RFC 5869)`
3. To enable the PPP support needed by the **esp_wireguard** component:
  - `(Top)` ---> `Component config` ---> `LWIP` ---> `Enable PPP support`
4. Since "_IPv6 support is alpha and probably broken_" in **esp_wireguard** component, it is recommended to disable it:
  - `(Top)` ---> `Component config` ---> `LWIP` ---> `Enable IPv6`

### Erase flash memory
Since we are going to store the keys in the NVS memory, it is recommended to erase the flash:
1. before flashing the client for the first time,
2. or, if you want to execute the project from a clean state.

```bash
idf.py -p PORT erase-flash
```

## X3DH Server and VPN Server
`Server` and `VPN Server` run inside Docker containers. Do not use `sudo` for the following commands if your user has permissions to run Docker commands.

```bash
# X3DH Server
sudo docker pull python:3.14.2-alpine3.23
cd server && sudo docker build -t x3dh-server:1.0 .

# VPN Server
sudo docker pull linuxserver/wireguard:1.0.20250521
```

```bash
# Build all the containers and start the service.
# Wait until the server is fully started.
./start_service.sh
```

```bash
# To stop the service
./stop_service.sh
```

```bash
# To stop and delete containers, networks and volumes
./down_service.sh
```

## VPN Configuration
Since the [esp_wireguard](https://github.com/trombik/esp_wireguard) repository is no longer maintained, if you try to use the component as it is, you are going to face issues with the newest versions of ESP-IDF. Mainly thanks to [issues](https://github.com/trombik/esp_wireguard/issues) opened during 2025, and [Kerem Erkan's post](https://keremerkan.net/posts/wireguard-mtu-fixes/) about MTU fixes, it was possible to make the component work again.

- **Overview:** the MCU performs NTP time synchronization and initializes the WireGuard tunnel. All runtime parameters used by the client are provided via the generated header `keys.h`.

- **Generate `keys.h`:** `generate_keys.py` extracts the required values from the WireGuard container `wg0.conf` and writes them to `client/main/keys.h`. You need to provide two arguments: the **host's local IP address** where the Docker containers are running, and the **peer number** assigned in the WireGuard server configuration, starting from 1.

```bash
python3 generate_keys.py <HOST_LOCAL_IP> <PEER_NUMBER>
```

- **Preshared Key (PSK) compatibility:** the `esp_wireguard` client used does not support `PresharedKey`. For that reason the helper script `update_wg_config.sh` comments out `PresharedKey` lines in the server configuration and replaces `PostUp`/`PostDown` rules to ensure proper forwarding/NAT and add an MSS clamp to avoid MTU issues. The script writes a flag file so it runs only once.

- **Runtime network notes:** `app_main.c` sets the WireGuard interface address from `WG_LOCAL_IP_ADDR` and, in the current code, forces a class-A netmask (`255.0.0.0`) and a gateway of `10.13.13.1`. The interface MTU is reduced to `1280` to prevent packet fragmentation/loss. If your network topology requires different netmask/gateway/MTU, update `keys.h` or modify `start_wireguard()` in `app_main.c` accordingly.

> ⚠️ **Known Issue:** Due to **CGNAT** (Carrier-Grade NAT) used by mobile hotspot, the client may not be able to reach the WireGuard server. If you experience connectivity issues, please try to connect the MCU to a different network.
  > If you are using a different client device (such as a PC), yet got the same issue, please check this [Kerem Erkan's post](https://keremerkan.net/posts/udp2raw-bypass-censoring-wireguard-protocol/).

> ⛔️ **Known Limitation:** `esp_wireguard` does not support _Ethernet interface_.

# How to run it
1. Start the containers:
```bash
./start_service.sh
```

2. Set the target for the client:
```bash
cd client && get_idf
idf.py set-target esp32
```

3. Build, flash and monitor the client:
```bash
idf.py build
idf.py -p PORT flash monitor
```

## Flow
The client will firstly connect to WiFi, then it will perform NTP time synchronization to get the correct time. After that, the WireGuard tunnel will be initialized to connect to the VPN Server. At this point, the client will be able to communicate with the X3DH Server, choosing one of the available options provided in the menu.

<p align="center">
  <img width="48%" src="docs/menu.png">
</p>