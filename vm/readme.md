# ambix_vm script

## Dependencies

- python3
- qemu
- sshfs

## Commands

- `create_disk <size> [--verbose=False]`
- `copy [--user=ambix] [--verbose=False]`
- `run [--image_path=None] [--disk_size=25] [--verbose=False]`

## Installation

1. Install dependencies with your distribution's package manager (e.g. `apt install python3 qemu sshfs`)
2. `pip install -r requirements.txt`

## Fresh VM install

1. Download an Ubuntu image [here](https://ftp.rnl.tecnico.ulisboa.pt/pub/ubuntu/releases/23.04/ubuntu-23.04-live-server-amd64.iso)

```sh
curl -X GET https://ftp.rnl.tecnico.ulisboa.pt/pub/ubuntu/releases/23.04/ubuntu-23.04-live-server-amd64.iso -o ubuntu.iso
```

2. Start VM install

```sh
./ambix_vm run ubuntu.iso --verbose=True
```

3. Go through VM install wizard
    a. Select language and keyboard layout
    b. **Opt out** of setting up disk as LVM group
    c. In your profile, just set everything to `ambix` (necessary for copy script to work)
    d. Install OpenSSH server
    e. Optional: Import SSH indentity for easier access
    f. Don't install any snaps

4. Reboot VM (ignore cdrom error) and close GUI

5. Run VM

```sh
./ambix_vm run
```

6. Copy Ambix files to VM

```sh
./ambix_vm copy
```

7. SSH into VM

```sh
ssh ambix@localhost -p 10022
```

## Running VM

1. Run VM

```sh
./ambix_vm run
```

2. SSH into VM

```sh
ssh ambix@localhost -p 10022
```
