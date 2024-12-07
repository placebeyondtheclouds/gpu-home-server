# GPU home server

## use cases

- running inference on models that require 24GB of VRAM
  - hosting ollama with open webui
- running training/inference code that requires CUDA v.11-12, needs Pascal architecture GPU
- render videos on CPU and GPU
- data engineering tasks

## to do

- [] mitigate https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3646
- [] reflash the BIOS with coreboot to remove the possibility of bootkits
- [] ARGB daemon
- [] wifi client

## hardware

- **NVIDIA TESLA P40**, PCIe 3.0 x16, TDP 250 W - 1649 元 **used**
- 2x PCIe 8pin to 1x **EPS 8pin adapter** 18AWG - was included with the GPU
  - might be an overkill as I could just use the spare 8pin CPU power cable from the PSU, but better make use of the two PCIe power cables
- custom made **长城战龙 240mm ARGB**-based water cooler solution for GPU - 459 元
  - it's basically a CPU water cooler with a custom plate for the GPU core plus a set custom cut thermal pads.
- thermal compound **Thermalright TF7**, 12.8 W/m-k, 2g tube, two tubes - 20 元
- **鱼巢 S9** mATX case 21L, support for 240mm water cooler (GPU) plus 120mm water cooler (CPU) - 134 元
- **鑫谷 GM650W** PSU, 650W 80plus(gold label rating) - 352 元
- **精粤 X99M GAMING D4 ARGB** motherboard, X99 chipset, DDR4, LGA2011-3, one PCIe 3.0 x16, NVMe - 286 元
  - CPU: 40 PCIe gen3 lanes, Chipset: 8 PCIe gen2 lanes
- **冰曼 KS120 white ARGB** 120mm CPU water cooler - 116 元
- **Intel Xeon E5-2697v4** CPU, 18 cores 36 threads, 2.3GHz base, 3.6GHz turbo, 145W TDP - 215 元 **used**
- **Samsung 32GB DDR4 2400T ECC REG dual rank x4** memory, two modules - 344 元 **used**
- **NVMe SSD 500GB** gen4 x4, left from laptop storage upgrade
- ~~**wifi dongle** Realtek rtl8812bu wifi5 usb3, bought before~~
- Dell **NVIDIA GT730 GPU**, PCIe gen2 x1 - 133 元 **used**

Total cost: 3700 元

## software

- Proxmox VE 8.3
  - NVIDIA drivers
  - NVIDIA container toolkit
- OpenWRT, VM
  - WiFi client
- OPNsense, VM
  - sensei/suricata
  - NAT, firewall, OpenVPN
- Debian 12, LXC for websites
  - docker stack: https://github.com/placebeyondtheclouds/gpu-webserver-docker-stack
    - ollama
    - open-webui
- Debian 12, LXC for training
  - conda, jupyter lab
- Debian 12, LXC for home network tools
  - docker
    - hashcat
    - jellyfin
    - nextcloud
    - https://runtipi.io/docs/apps-available
    - https://docs.techdox.nz/paperless/
    - https://www.linuxserver.io/
      - https://fleet.linuxserver.io/image?name=linuxserver/code-server
      - https://fleet.linuxserver.io/image?name=linuxserver/transmission
      - https://fleet.linuxserver.io/image?name=linuxserver/jellyfin

## principles

- only sone websites are exposed to the internet through a reverse proxy plus waf plus cloudflare public dns with basic protections
- all other services are accessed through VPN
- gpu is shared between LXCs

## hardware setup pictures

| ![pic1](/pictures/2024-12-04%2013.54.50.jpg)  | ![pic4](/pictures/2024-12-04%2015.00.19.jpg)  | ![pic7](/pictures/2024-12-04%2015.19.18.jpg)  |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic10](/pictures/2024-12-04%2015.21.53.jpg) | ![pic13](/pictures/2024-12-04%2015.56.54.jpg) | ![pic16](/pictures/2024-12-04%2015.57.07.jpg) |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic19](/pictures/2024-12-04%2015.58.38.jpg) | ![pic22](/pictures/2024-12-04%2015.58.55.jpg) | ![pic25](/pictures/2024-12-04%2016.03.10.jpg) |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic28](/pictures/2024-12-04%2016.04.41.jpg) | ![pic31](/pictures/2024-12-04%2016.07.58.jpg) | ![pic34](/pictures/2024-12-04%2016.08.32.jpg) |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic37](/pictures/2024-12-04%2016.22.17.jpg) | ![pic2](/pictures/2024-12-04%2020.35.55.jpg)  | ![pic5](/pictures/2024-12-04%2020.38.57.jpg)  |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic8](/pictures/2024-12-04%2020.42.30.jpg)  | ![pic11](/pictures/2024-12-04%2020.46.02.jpg) | ![pic14](/pictures/2024-12-04%2020.52.21.jpg) |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic17](/pictures/2024-12-04%2020.53.43.jpg) | ![pic20](/pictures/2024-12-04%2020.54.02.jpg) | ![pic23](/pictures/2024-12-04%2020.54.08.jpg) |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic26](/pictures/2024-12-04%2020.57.34.jpg) | ![pic29](/pictures/2024-12-04%2020.59.07.jpg) | ![pic32](/pictures/2024-12-04%2020.59.14.jpg) |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic35](/pictures/2024-12-04%2020.59.20.jpg) | ![pic3](/pictures/2024-12-04%2021.23.26.jpg)  | ![pic6](/pictures/2024-12-04%2021.27.08.jpg)  |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic9](/pictures/2024-12-04%2021.30.54.jpg)  | ![pic12](/pictures/2024-12-04%2021.30.58.jpg) | ![pic15](/pictures/2024-12-04%2021.42.22.jpg) |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic18](/pictures/2024-12-04%2021.52.20.jpg) | ![pic21](/pictures/2024-12-04%2022.02.57.jpg) | ![pic24](/pictures/2024-12-04%2022.04.49.jpg) |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic27](/pictures/2024-12-04%2022.04.58.jpg) | ![pic30](/pictures/2024-12-04%2022.08.40.jpg) | ![pic33](/pictures/2024-12-04%2022.16.36.jpg) |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic36](/pictures/2024-12-04%2022.18.54.jpg) | ![pic38](/pictures/2024-12-04%2021.11.59.jpg) | ![pic39](/pictures/2024-12-05%2008.14.20.jpg) |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic40](/pictures/2024-12-05%2008.14.39.jpg) | ![pic41](/pictures/2024-12-05%2008.14.47.jpg) | ![pic42](/pictures/2024-12-05%2010.33.03.jpg) |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic43](/pictures/2024-12-05%2010.33.17.jpg) | ![pic44](/pictures/2024-12-05%2010.33.32.jpg) | ![pic45](/pictures/2024-12-05%2010.34.00.jpg) |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic46](/pictures/2024-12-05%2011.18.56.jpg) | ![pic47](/pictures/2024-12-05%2011.51.31.jpg) | ![pic48](/pictures/2024-12-05%2011.51.50.jpg) |
| :-------------------------------------------: | :-------------------------------------------: | :-------------------------------------------: |
| ![pic49](/pictures/2024-12-05%2012.01.30.jpg) | ![pic50](/pictures/2024-12-06%2007.05.46.jpg) |                                               |

## hardware setup process

- assemble minimal setup with CPU, RAM, the small GPU, PSU, motherboard and get it to POST

- there are no rules for populating memory banks because there are 4 slots and 4 channels

- boot Ubuntu Live cd and check if the P40 is recognized

- check BIOS version, reflash from the official website just in case

- remove the P40 and install the waterblock on it

- CPU waterblock fan connected to the CFAN1 PWM fan header (FAN1 in BIOS), GPU waterblock fan connected to the SFAN1 PWM header (FAN2 in BIOS)

- set up BIOS

  - PCI subsystem settings ->
    - Enable above 4G decoding (otherwise will be faced with `Insufficient PCI resources detected`)
    - Enable Re-Size BAR Support [explainer](https://www.reddit.com/r/pcmasterrace/comments/1b4sy75/comment/kt24k82/)
    - Enable SR-IOV Support
    - MMIOHBase set to 2T
  - CSM configuration -> UEFI only
  - intelrcsetup
    - advanced power management configuration -> power technology -> enegry efficient
    - PCH configuration -> disable sSATA and SATA controllers

- install the P40

## software setup process

### hypervisor

- boot Proxmox VE 8.3 live cd, hit `e` and add `nomodeset` to the kernel command line, `ctrl` + `x` to boot (because GT830 is too old for the drivers in proxmox)

#### set up virtualization (IOMMU and VFIO), blacklist default drivers

- `nano /etc/default/grub`

  - ```
    GRUB_CMDLINE_LINUX_DEFAULT="intel_iommu=on iommu=pt nomodeset"

    ```

- ```bash
  tee /etc/modprobe.d/blacklist.conf <<-'EOF'
  blacklist nouveau
  blacklist snd_hda_intel
  EOF
  ```

- ```bash
  tee /etc/modules-load.d/modules.conf <<-'EOF'
  nvidia
  nvidia-modeset
  nvidia_uvm
  vfio
  vfio_iommu_type1
  vfio_pci
  EOF
  ```

- ```
  tee /etc/udev/rules.d/70-nvidia.rules <<-'EOF'
  KERNEL=="nvidia", RUN+="/bin/bash -c '/usr/bin/nvidia-smi -L && /bin/chmod 666 /dev/nvidia*'"
  KERNEL=="nvidia_modeset", RUN+="/bin/bash -c '/usr/bin/nvidia-modprobe -c0 -m && /bin/chmod 666 /dev/nvidia-modeset*'"
  KERNEL=="nvidia_uvm", RUN+="/bin/bash -c '/usr/bin/nvidia-modprobe -c0 -u && /bin/chmod 666 /dev/nvidia-uvm*'"
  EOF
  ```

- ```
  tee /etc/modprobe.d/vfio.conf <<-'EOF'
  softdep nouveau pre: vfio-pci
  softdep snd_hda_intel pre: vfio-pci
  EOF
  ```

- `echo "options vfio_iommu_type1 allow_unsafe_interrupts=1" > /etc/modprobe.d/iommu_unsafe_interrupts.conf`

- `update-initramfs -u && update-grub`

- `dmesg | grep -e DMAR -e IOMMU`

  - should see `DMAR: Intel(R) Virtualization Technology for Directed I/O`

#### set up updates

```bash
tee /etc/apt/sources.list <<-'EOF'
#deb http://ftp.debian.org/debian bookworm main contrib
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm main contrib

#deb http://ftp.debian.org/debian bookworm-updates main contrib
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm-updates main contrib

# security updates
#deb http://security.debian.org bookworm-security main contrib
deb https://security.debian.org/debian-security bookworm-security main contrib

# deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription
deb https://mirrors.tuna.tsinghua.edu.cn/proxmox/debian/pve bookworm pve-no-subscription
EOF
```

`rm /etc/apt/sources.list.d/pve-enterprise.list`

```
cat > /etc/apt/sources.list.d/ceph.list << EOF
deb http://download.proxmox.com/debian/ceph-reef bookworm no-subscription
EOF
```

`apt update && apt dist-upgrade -y`

`sed -Ezi.bak "s/(Ext.Msg.show\(\{\s+title: gettext\('No valid sub)/void\(\{ \/\/\1/g" /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js && systemctl restart pveproxy.service`

`apt install mc screen iputils-tracepath stress s-tui iptraf-ng unzip lshw lm-sensors freeipmi-tools htop btop -y`

`sensors-detect --auto`

#### tune power consumption

- `apt install powertop && powertop --auto-tune`

#### test CPU stability

- `apt install stress s-tui`
- `stress --cpu 38 --timeout 60`

#### install NVIDIA drivers

`nvidia-smi` binary has been moved to `nvidia-cuda-driver` package (https://forums.developer.nvidia.com/t/nvidia-smi-missing-for-565-drivers-debian-12-packages/311702/5)

must lock to a certain driver version on the host and in the LXC.

```bash
apt install pve-headers-$(uname -r)
curl -fSsL https://developer.download.nvidia.com/compute/cuda/repos/debian12/x86_64/3bf863cc.pub | gpg --dearmor | tee /usr/share/keyrings/nvidia-drivers.gpg > /dev/null 2>&1
apt update
apt install dirmngr ca-certificates software-properties-common apt-transport-https dkms -y
echo 'deb [signed-by=/usr/share/keyrings/nvidia-drivers.gpg] https://developer.download.nvidia.com/compute/cuda/repos/debian12/x86_64/ /' | tee /etc/apt/sources.list.d/nvidia-drivers.list
apt update
apt install cuda-drivers-565 nvtop -y
apt list --installed | grep nvidia
reboot
```

- `lspci -nnk | grep -i nvidia`
  - should see `Kernel driver in use: nvidia`
- `nvidia-smi -i 0 -q`

#### ARGB

- install https://github.com/CalcProgrammer1/OpenRGB as a daemon

```bash

```

### openwrt x86 VM

- `wget https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/openwrt-23.05.5-x86-64-generic-ext4-combined.img.gz`
- `gunzip openwrt-*.img.gz`
- `qemu-img resize -f raw openwrt-*.img 8G`
- create new VM (no drives, SeaBIOS)
- `qm importdisk 103 openwrt-23.05.5-x86-64-generic-ext4-combined.img local-lvm`
- set the disk to VirtIO block, discard=enabled, add
- change boot order
- add usb wifi dongle

boot. ssh into it, user `root`, password is blank.

add eth nic to connect to the internet temporarily, configure opkg feed links to the servers(mirror-03.infra.openwrt.org or downloads.openwrt.org or thatever that is working), install packages for the usb wifi dongle chip and `wpa-supplicant-openssl` (for WPA3), reboot connect to the wifi

continue expanding root filesystem

- `opkg update && opkg install lsblk fdisk losetup resize2fs`
- `lsblk -o PATH,SIZE,PARTUUID`
- `lsblk -o PATH,SIZE,PARTUUID > /root/lsblk_old.txt`
- `cat /boot/grub/grub.cfg`
- `fdisk /dev/sda` -> `p` -> `d` -> `2` -> `n` -> `p` -> `2` -> 33792 enter -> `enter` -> `n` -> `w`
- ```
  BOOT="$(sed -n -e "/\s\/boot\s.*$/{s///p;q}" /etc/mtab)"
  DISK="${BOOT%%[0-9]*}"
  PART="$((${BOOT##*[^0-9]}+1))"
  ROOT="${DISK}${PART}"
  LOOP="$(losetup -f)"
  losetup ${LOOP} ${ROOT}
  fsck.ext4 -y -f ${LOOP}
  resize2fs ${LOOP}
  reboot
  ```

### OPNsense VM

- https://opnsense.org/download/

user `installer`, password `opnsense`

### common setup for all LXCs

- download Debian-12 template and create unprivileged LXC with Debian 12

- add GPU to the config, run `ls -al /dev/nv* | grep -v nvme` edit `nano /etc/pve/lxc/100.conf` according to the output:

```
lxc.cgroup2.devices.allow: c 195:0 rw
lxc.cgroup2.devices.allow: c 195:255 rw
lxc.cgroup2.devices.allow: c 195:254 rw
lxc.cgroup2.devices.allow: c 234:0 rw
lxc.cgroup2.devices.allow: c 234:1 rw
lxc.cgroup2.devices.allow: c 10:144 rw
lxc.mount.entry: /dev/nvidia0 dev/nvidia0 none bind,optional,create=file
lxc.mount.entry: /dev/nvidiactl dev/nvidiactl none bind,optional,create=file
lxc.mount.entry: /dev/nvidia-modeset dev/nvidia-modeset none bind,optional,create=file
lxc.mount.entry: /dev/nvidia-uvm dev/nvidia-uvm none bind,optional,create=file
lxc.mount.entry: /dev/nvidia-uvm-tools dev/nvidia-uvm-tools none bind,optional,create=file
lxc.mount.entry: /dev/nvram dev/nvram none bind,optional,create=file
```

- start the LXC

- add user `admin` with sudo rights: `adduser admin && usermod -aG sudo admin`

- `dpkg-reconfigure locales` and set en_US.UTF-8 as default

- `timedatectl set-timezone Asia/Shanghai`

- set up updates

```bash
tee /etc/apt/sources.list <<-'EOF'
# 默认注释了源码镜像以提高 apt update 速度，如有需要可自行取消注释
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm main contrib non-free non-free-firmware
# deb-src https://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm main contrib non-free non-free-firmware

deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm-updates main contrib non-free non-free-firmware
# deb-src https://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm-updates main contrib non-free non-free-firmware

deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm-backports main contrib non-free non-free-firmware
# deb-src https://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm-backports main contrib non-free non-free-firmware

# 以下安全更新软件源包含了官方源与镜像站配置，如有需要可自行修改注释切换
deb https://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
# deb-src https://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware

EOF

apt update && apt upgrade -y
```

- `apt install linux-headers-amd64 -y`

- `apt install screen curl gpg -y`

- install NVIDIA drivers, same commands as for the host minus the `pve-headers-$(uname -r)` package

- install nvidia-container-toolkit

```bash
apt install nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
```

- `sed -i 's/#no-cgroups = false/no-cgroups = true/' /etc/nvidia-container-runtime/config.toml`

- check with `nvidia-container-cli -k -d /dev/tty info`

- `logout`

#### Debian LXC for websites

- install docker engine

```
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
sudo usermod -aG docker $USER
```

- test with `docker info | grep -i runtime` and `docker run --rm --runtime=nvidia --gpus all ubuntu nvidia-smi`

- add ssh key and deploy my `GPU webserver docker stack` using DOCKER_HOST

#### Debian LXC for training

## Docker security

- https://github.com/wsargent/docker-cheat-sheet?tab=readme-ov-file#security

## Results

- noise around 38dB at 1 meter
  <br><img src="./pictures/noise.png" alt="screenshot" width="30%">
- idle at 64W, 120W with GPU VRAM loaded and idle, 250W with GPU under load
- usb dongles on `rtl8812bu` and `mt7921au` didn't work with OpenWRT, `mt7612u` was working but very unstable.
- must set up BIOS before installing the P40, because in some card-slot combinations with the P40 and the GT730 the system won't POST or will throw `Insufficient PCI resources detected` error

## Conclusion

- should have chosen a less power hungry CPU (like E5-2650v4 or something that is still running the memory at 2400MT/s), there is no need in a CPU this powerful
- will have to use a NGFF wifi card with PCIe passthrough
- P40 is not very power efficient at idle when the VRAM is loaded
- the motherboard has PCIe gen3, so any newer GPU will work but data transfer speeds will be limited to gen3

## 感谢

感谢可可给我借一个很好用的键盘

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
- https://itgpt.net/note-book/%E6%B4%8B%E5%9E%83%E5%9C%BE%E4%B8%BB%E6%9C%BA/CPU%E9%B8%A1%E8%A1%80BIOS
- https://www.servethehome.com/intel-xeon-e5-2600-v4-broadwell-ep-launched/intel-xeon-e5-2600-v4-family-comparison/
- https://www.reddit.com/r/homelab/comments/lli4mg/intel_e5_2600_v4_series_comparison/
- https://pmcvtm.com/adding-openrgb-to-proxmox
- https://gist.github.com/subrezon/b9aa2014343f934fbf69e579ecfc8da8
- https://digitalspaceport.com/proxmox-multi-gpu-passthru-for-lxc-and-docker-ai-homelab-server/
- https://forum.openwrt.org/t/howto-resizing-root-partition-on-x86/140631
- https://docs.nvidia.com/deploy/driver-persistence/index.html
