# ambix_vm script

## Dependencies:
- python3
- qemu
- sshfs

## Commands:
- `create_disk <size> [--verbose=False]`
- `copy [--user=ambix] [--verbose=False]`
- `run [--image_path=None] [--disk_size=25] [--verbose=False]`

## Installation
1. Install dependencies with your distribution's package manager
2. `pip install -r requirements.txt`

## Running
1. Download an Ubuntu [here](https://ftp.rnl.tecnico.ulisboa.pt/pub/ubuntu/releases/23.04/ubuntu-23.04-live-server-amd64.iso)
```sh
curl -X GET https://ftp.rnl.tecnico.ulisboa.pt/pub/ubuntu/releases/23.04/ubuntu-23.04-live-server-amd64.iso -o ubuntu.iso
```
2. 
```sh
./ambix_vm <path to ubuntu iso> --verbose=True
```
3. Finish installation, don't forget to enable ssh.
4. Reboot and it should now run
