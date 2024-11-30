# GPU home server

## use cases

- running inference on models that require 24GB of VRAM
  - hosting ollama with open webui
- running training/inference code that requires CUDA v.11-12, needs Pascal architecture GPU

## hardware

- **NVIDIA TESLA P40**, PCIe 3.0 x16, TDP 250 W - 1649 元 **used**
- 2x PCIe 8pin to 1x **EPS 8pin adapter** - 15 元
  - might be an overkill as I could just use the spare 8pin CPU power cable from the PSU, but better make use of the two PCIe power cables
- custom made **长城战龙 240mm ARGB**-based water cooler solution for GPU - 459 元
  - it's basically a CPU water cooler with a custom plate for the GPU core. I might have paid 300 元 for a small piece of copper hahahahahaha.
- thermal compound **Thermalright TF7**, 12.8 W/m-k, 2g tube, four tubes - 40 元
- **鱼巢 S9** mATX case 21L, support for 240mm water cooler (GPU) plus 120mm water cooler (CPU) - 134 元
- **鑫谷 GM650W** PSU, 650W 80plus(gold label rating) - 352 元
- **精粤 X99M GAMING D4** motherboard, X99 chipset, DDR4, LGA2011-3, one PCIe 3.0 x16, NVMe - 275 元
  - CPU: 40 PCIe gen3 lanes
  - Chipset: 8 PCIe gen2 lanes
- **冰曼 KS120 white ARGB** 120mm CPU water cooler - 116 元
- **Intel Xeon E5-2697v4** CPU, 18 cores 36 threads, 2.3GHz base, 3.6GHz turbo, 145W TDP - 215 元 **used**
- **Samsung 32GB DDR4 2400T ECC REG dual rank x4** memory, two modules - 344 元 **used**
- **NVMe SSD 500GB**, left from laptop storage upgrade
- NVME SSD **heatsink**, bought before
- dual 5dbi antenna **wifi dongle** on Realtek rtl8812bu chip, wifi5 usb3.0, bought before
  - supported in-kernel since Linux kernel 6.2 (2023) but kernel 6.12 (2024) is recommended due to stability and performance enhancements
- Dell NVIDIA GT730 GPU, PCIe gen2 x1 - 120 元 **used**

## software

- Proxmox VE 8.2
  - GPU passthrough
  - NVIDIA drivers
  - NVIDIA container toolkit
- OPNsense, VM
  - sensei/suricata
  - NAT, firewall, OpenVPN
- Debian, LXC for websites
  - docker stack: https://github.com/placebeyondtheclouds/gpu-webserver-docker-stack
    - ollama
    - open-webui
- Debian, LXC for training
  - conda, jupyter lab
- Debian, LXC for home network tools
  - docker
    - hashcat
    - jellyfin
    - nextcloud

## principles

- only sone websites are exposed to the internet through a reverse proxy plus waf plus cloudflare public dns with basic protections
- all other services are accessed through VPN
- gpu is shared between LXCs

## hardware setup pictures

## software setup process

### hypervisor

### OPNsense VM

### Debian LXC for websites

### Debian LXC for training

## references

- https://arnon.dk/matching-sm-architectures-arch-and-gencode-for-various-nvidia-cards/
- https://www.playtool.com/pages/psuconnectors/connectors.html
- https://www.coolermaster.com/en-global/guide-and-resources/what-is-80-plus-efficiency/
- https://en.wikipedia.org/wiki/Intel_X99
- https://jginyue.com.cn/index/Article/show/cat_id/48/id/195
- https://ark.intel.com/content/www/us/en/ark/products/91755/intel-xeon-processor-e5-2697-v4-45m-cache-2-30-ghz.html
- https://github.com/morrownr/USB-WiFi/blob/main/home/USB_WiFi_Adapters_that_are_supported_with_Linux_in-kernel_drivers.md#chipset---realtek-rtl8812bu---supported-in-kernel-since-linux-kernel-62-2023-but-kernel-612-2024-is-recommended-due-to-stability-and-performance-enhancements
- https://www.thermalright.com/product/tf7-2g/
- https://www.techpowerup.com/gpu-specs/geforce-gt-730.c2590
- https://www.techpowerup.com/gpu-specs/tesla-p40.c2878
- https://www.bilibili.com/video/BV1gz4y187VR/
- https://www.bilibili.com/video/BV1co4y1H7KJ
