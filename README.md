# GPU home server

## use cases

- running inference on models that require 24GB of VRAM
  - hosting ollama with open webui
- running training/inference code that requires CUDA v.11-12, needs Pascal architecture GPU

## hardware

- `NVIDIA TESLA P40`, **used** - 1649 yuan
- custom made 240mm water cooler for GPU - 459 yuan
  - it's basically a CPU water cooler with a custom plate for the GPU core. I might have paid 300 yuan for a small piece of copper hahahahahaha.
- thermal grease `Thermalright TF7` 2g tube, two tubes - 22 yuan
- `鱼巢S9` mATX case 21L, support for 240mm water cooler (GPU) plus 120mm water cooler (CPU) - 134 yuan
- `鑫谷 AN650` PSU, 650W 80plus(lowest white label rating) - 221 yuan
- `精粤 X99M GAMING D4` motherboard, X99 chipset, DDR4, LGA2011, PCIe 3.0 x16 - 275 yuan
  - https://www.jginyue.com/index/Article/show/cat_id/48/id/168.html
- `冰曼 KS120 white` 120mm water cooler - 106 yuan
- `Intel Xeon E5-2697v4` CPU, **used**, socket lga 2011, 18 cores 36 threads, 2.3GHz base clock, 3.6GHz turbo clock, 145W TDP - 215 yuan
  - https://ark.intel.com/content/www/us/en/ark/products/91755/intel-xeon-processor-e5-2697-v4-45m-cache-2-30-ghz.html
- `Samsung 32GB DDR4 2400T ECC REG dual rank x4` memory module x 2, **used** - 344 yuan
- NVMe ssd 500GB, left from laptop upgrade - 0 yuan
- dual 5dbi antenna wifi dongle on Realtek rtl8812bu chip, wifi5 usb3.0, bought before
  - supported in-kernel since Linux kernel 6.2 (2023) but kernel 6.12 (2024) is recommended due to stability and performance enhancements
  - https://github.com/morrownr/USB-WiFi/blob/main/home/USB_WiFi_Adapters_that_are_supported_with_Linux_in-kernel_drivers.md#chipset---realtek-rtl8812bu---supported-in-kernel-since-linux-kernel-62-2023-but-kernel-612-2024-is-recommended-due-to-stability-and-performance-enhancements

Total cost: 3438 yuan
