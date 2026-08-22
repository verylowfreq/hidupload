# catupload

Command-line uploader for a WCH CH32V203 CAT bootloader.

https://github.com/verylowfreq/catbootloader_ch32v20x

It speaks a simple USB Vendor-class bulk protocol to erase, program, verify, and reset the device after flashing.

## Features
- Writes a raw binary to a target address (with optional offset).
- Automatically erases the required flash pages before programming.
- Optional CRC16-CCITT verification after programming.
- Resets the device when done.

## Requirements
- A CH32V20x device running a compatible bootloader that exposes a USB Vendor-class bulk interface.
- USB access for your OS user account, with a driver that allows Vendor-class bulk transfers.


## Usage and example
```sh
catupload --bin PATH --address ADDR [options]
```

```sh
# Program with an offset, then verify
catupload --bin firmware.bin --address 0x08000000 --offset 0x2000 --verify
```

```sh
# Wait up to about 10 seconds for the device to re-enumerate after a bootloader reset
catupload --bin firmware.bin --address 0x08000000 --retries 100 --retry-interval 100
```

## Build
```sh
cargo build --release
```

## Options
- `--bin PATH` Path to the binary to write.
- `--address ADDR` Base address to write to (hex or decimal).
- `--offset OFFSET` Offset added to the base address (default: 0).
- `--vid VID` USB VID (default: 0xf055).
- `--pid PID` USB PID (default: 0x6585).
- `--retries COUNT` Extra open attempts after the first failure (default: 0).
- `--retry-interval MSEC` Interval between open attempts (default: 100).
- `--verify` Verify with CRC16-CCITT after programming.

## Notes
- Erase is always performed automatically before programming.
- The erase range is expanded to 4 KB page boundaries as needed.
- If multiple devices match the requested VID/PID, the tool aborts without programming.
  This is never retried, because waiting cannot resolve it.
- After a 1200bps touch from the Arduino IDE the device needs time to re-enumerate.
  Pass `--retries 100 --retry-interval 100` to wait up to about 10 seconds for it to appear.
  Retrying covers enumeration, opening, and claiming the interface, so it also rides out
  the window where the device is visible but its driver is not bound yet.
- The tool resets the device after a successful run.
