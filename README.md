# catupload

Command-line uploader for a WCH CH32V203 CAT bootloader.

https://github.com/verylowfreq/catbootloader_ch32v20x

It speaks a simple USB Vendor-class bulk protocol to erase, program, read back, verify, and reset the device.

## Requirements
- A CH32V20x device running a compatible bootloader that exposes a USB Vendor-class bulk interface.
- USB access for your OS user account, with a driver that allows Vendor-class bulk transfers.
- `reset-bootloader` additionally requires bootloader support for opcode 9 (`CMD_RESET_BOOTLOADER`).

## Build
```sh
cargo build --release
```

## Usage
```sh
catupload <COMMAND> [OPTIONS]
```

| Command | Description |
| --- | --- |
| `flash` | Write a binary to flash (erase, program, optionally verify, then reset). |
| `erase` | Erase a range of flash. |
| `read` | Read flash into a file. |
| `verify` | Compare a binary against the device using CRC16. |
| `crc` | Print the CRC16 of a range on the device. |
| `probe` | Connect, read IDENT and exit without touching flash. |
| `reset` | Reset the device, so the application starts. |
| `reset-bootloader` | Reset the device and stay in the bootloader. |
| `list` | List matching USB devices without opening them. |
| `help` | Print help. `catupload help flash` describes one command. |

### Global options
These apply to every command that talks to the device, and may be given before or after it.

- `--vid VID` USB VID (default: 0xf055).
- `--pid PID` USB PID (default: 0x6585).
- `--retries COUNT` Extra open attempts after the first failure (default: 0).
- `--retry-interval MSEC` Interval between open attempts (default: 100).

## Commands

### flash
```sh
catupload flash --bin firmware.bin --address 0x08004000
catupload flash --bin firmware.bin --address 0x08004000 --offset 0x2000 --verify
```
- `--bin PATH` Path to the binary to write.
- `--address ADDR` Base address to write to (hex or decimal).
- `--offset OFFSET` Offset added to the base address (default: 0).
- `--verify` Verify with CRC16-CCITT after programming.
- `--no-reset` Leave the device in the bootloader instead of resetting.

Erase is performed automatically before programming, and the erase range is expanded to 4 KB page boundaries as needed.

### erase
```sh
catupload erase --address 0x08004000 --size 0x4000
```
- `--address ADDR` Base address. Must be 4096-byte aligned.
- `--size SIZE` Number of bytes. Must be a multiple of 4096.

Unlike `flash`, this does **not** widen the range for you — a misaligned range is refused, with the aligned equivalent suggested in the error.

### read
```sh
catupload read --address 0x08004000 --size 0x1000 --out dump.bin
```
- `--address ADDR` Base address to read from.
- `--size SIZE` Number of bytes to read.
- `--out PATH` File to write the data to.

### verify / crc
```sh
catupload verify --bin firmware.bin --address 0x08004000
catupload crc --address 0x08004000 --size 0x1000
```
`verify` takes the same `--bin` / `--address` / `--offset` as `flash`. `crc` takes `--address` and `--size` and just prints the device's CRC16.

### probe / reset / reset-bootloader / list
```sh
catupload probe
catupload reset
catupload reset-bootloader
catupload list --vid 0xf055 --pid 0x6585
```

## Memory map

The first 16 KiB of flash is the CAT bootloader itself, so **application images start at `0x08004000`**.

| Region | Purpose |
| --- | --- |
| `0x08000000` .. `0x08004000` | CAT bootloader (also visible at `0x00000000`) |
| `0x08004000` .. | Application |
| `0x1fff8000` .. `0x1ffff000` | WCH system flash |

`flash` and `erase` refuse any range overlapping the bootloader or the WCH system flash, including via the `0x00000000` alias. Nothing is sent to the device when a range is refused.

## Notes
- If multiple devices match the requested VID/PID, the tool aborts without programming. This is never retried, because waiting cannot resolve it. Use `list` to see what matched.
- After a 1200bps touch from the Arduino IDE the device needs time to re-enumerate. Pass `--retries 100 --retry-interval 100` to wait up to about 10 seconds for it to appear. Retrying covers enumeration, opening, and claiming the interface, so it also rides out the window where the device is visible but its driver is not bound yet.
- `reset-bootloader` only works while you can already talk to the bootloader. It cannot pull a *running application* into the bootloader — for that, use the double-reset entry or the Arduino IDE's 1200bps touch.
- **`read` and `crc` do not range-check their address.** The bootloader dereferences the address directly, so an out-of-range value faults the MCU and leaves the tool waiting for a response that never arrives. Double-check the address until the bootloader can report the real flash size.
