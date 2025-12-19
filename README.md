# hidupload

Command-line uploader for a WCH CH32V203 HID bootloader.

https://github.com/verylowfreq/hidbootloader_ch32v203

It speaks a simple HID protocol to erase, program, verify, and reset the device after flashing.

## Features
- Writes a raw binary to a target address (with optional offset).
- Optional page erase before programming.
- Optional CRC16-CCITT verification after programming.
- Resets the device when done.

## Requirements
- A CH32V203 device running a compatible HID bootloader.
- USB HID access for your OS user account.


## Usage and example
```sh
hidupload --bin PATH --address ADDR [options]
```

```sh
# Program with an offset, erase first, then verify
hidupload --bin firmware.bin --address 0x08000000 --offset 0x2000 --erase --verify
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
- `--product NAME` Product string to match (default: "HID Bootloader").
  Use an empty string to skip the check.
- `--erase` Erase before programming.
- `--verify` Verify with CRC16-CCITT after programming.

## Notes
- Erase requires the start address and size to be 4 KB aligned.
- Without erase operation, programming will fail.
- The tool resets the device after a successful run.
