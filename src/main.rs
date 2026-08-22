use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
enum Command {
    Ident = 1,
    Erase = 2,
    ProgramStart = 3,
    ProgramAppend = 4,
    Flush = 5,
    Read = 6,
    Reset = 7,
    Crc = 8,
    ResetBootloader = 9,
}

const TIMEOUT: Duration = Duration::from_millis(100);
const WRITE_BLOCK_SIZE: usize = 54;
const FLUSH_PAGE_SIZE: usize = 4096;
const PACKET_SIZE: usize = 64;
/// The device clamps a READ request to this many bytes per packet.
const READ_BLOCK_SIZE: usize = 62;

/// Regions that must never be written or erased.
///
/// CH32V20x maps the main flash at both 0x0000_0000 and 0x0800_0000, so the
/// bootloader has to be protected at both aliases or the guard is trivially
/// sidestepped by using the other address.
const PROTECTED_REGIONS: &[(u32, u32, &str)] = &[
    (0x0800_0000, 0x4000, "CAT bootloader"),
    (0x0000_0000, 0x4000, "CAT bootloader (alias)"),
    (0x1fff_8000, 0x7000, "WCH system flash"),
];

#[derive(Debug, Parser)]
#[command(author, version, about = "CAT bootloader uploader")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// VID (default 0xf055)
    #[arg(long, global = true, default_value = "0xf055", value_parser = parse_u16, value_name = "VID")]
    vid: u16,
    /// PID (default 0x6585)
    #[arg(long, global = true, default_value = "0x6585", value_parser = parse_u16, value_name = "PID")]
    pid: u16,
    /// Extra open attempts after the first failure (default 0)
    #[arg(long, global = true, default_value = "0", value_parser = parse_u32, value_name = "COUNT")]
    retries: u32,
    /// Interval between open attempts in msec (default 100)
    #[arg(long, global = true, default_value = "100", value_parser = parse_u32, value_name = "MSEC")]
    retry_interval: u32,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Write a binary to flash (erase, program, optionally verify, then reset)
    Flash(FlashArgs),
    /// Erase a range of flash
    Erase(EraseArgs),
    /// Read flash into a file
    Read(ReadArgs),
    /// Compare a binary against the device using CRC16
    Verify(VerifyArgs),
    /// Print the CRC16 of a range on the device
    Crc(CrcArgs),
    /// Connect, read IDENT and exit without touching flash
    Probe,
    /// Reset the device (the application starts)
    Reset,
    /// Reset the device and stay in the bootloader
    #[command(alias = "reset_bootloader")]
    ResetBootloader,
    /// List matching USB devices without opening them
    List,
}

#[derive(Debug, Args)]
struct FlashArgs {
    /// Path to binary firmware
    #[arg(long, value_name = "PATH")]
    bin: PathBuf,
    /// Base address (e.g. 0x08004000)
    #[arg(long, value_parser = parse_u32, value_name = "ADDR")]
    address: u32,
    /// Offset added to base address
    #[arg(long, default_value = "0", value_parser = parse_u32, value_name = "OFFSET")]
    offset: u32,
    /// Verify CRC16 after programming
    #[arg(long, default_value_t = false)]
    verify: bool,
    /// Leave the device in the bootloader instead of resetting
    #[arg(long, default_value_t = false)]
    no_reset: bool,
}

#[derive(Debug, Args)]
struct EraseArgs {
    /// Base address, must be 4096-byte aligned
    #[arg(long, value_parser = parse_u32, value_name = "ADDR")]
    address: u32,
    /// Number of bytes to erase, must be a multiple of 4096
    #[arg(long, value_parser = parse_u32, value_name = "SIZE")]
    size: u32,
}

#[derive(Debug, Args)]
struct ReadArgs {
    /// Base address to read from
    #[arg(long, value_parser = parse_u32, value_name = "ADDR")]
    address: u32,
    /// Number of bytes to read
    #[arg(long, value_parser = parse_u32, value_name = "SIZE")]
    size: u32,
    /// File to write the data to
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Path to binary firmware
    #[arg(long, value_name = "PATH")]
    bin: PathBuf,
    /// Base address (e.g. 0x08004000)
    #[arg(long, value_parser = parse_u32, value_name = "ADDR")]
    address: u32,
    /// Offset added to base address
    #[arg(long, default_value = "0", value_parser = parse_u32, value_name = "OFFSET")]
    offset: u32,
}

#[derive(Debug, Args)]
struct CrcArgs {
    /// Base address
    #[arg(long, value_parser = parse_u32, value_name = "ADDR")]
    address: u32,
    /// Number of bytes
    #[arg(long, value_parser = parse_u32, value_name = "SIZE")]
    size: u32,
}

trait BootTransport {
    fn send(
        &self,
        command: Command,
        param1: u32,
        param2: u32,
        data: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>>;
    fn send_without_response(
        &self,
        command: Command,
        param1: u32,
        param2: u32,
        data: &[u8],
    ) -> Result<()>;
    fn kind(&self) -> &'static str;
}

struct Bootloader {
    transport: Box<dyn BootTransport>,
}

impl Bootloader {
    fn new(transport: Box<dyn BootTransport>) -> Self {
        Self { transport }
    }

    fn transport_kind(&self) -> &'static str {
        self.transport.kind()
    }

    fn get_ident(&self) -> Result<String> {
        let resp = self.send(Command::Ident, 0, 0, &[], TIMEOUT)?;
        let len = *resp.get(1).unwrap_or(&0) as usize;
        let end = len.saturating_add(2).min(resp.len());
        let text = std::str::from_utf8(&resp[2..end]).context("IDENT returned invalid UTF-8")?;
        Ok(text.to_string())
    }

    fn write(&self, start_address: u32, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut remaining = data;
        let mut address = start_address;
        let mut pos_in_page: usize = 0;

        println!("Program start");

        while !remaining.is_empty() {
            if pos_in_page == 0 {
                self.send_without_response(Command::ProgramStart, address, 0, &[])?;
            }

            let mut write_len = remaining.len().min(WRITE_BLOCK_SIZE);
            if pos_in_page + write_len > FLUSH_PAGE_SIZE {
                write_len = FLUSH_PAGE_SIZE - pos_in_page;
            }

            let chunk = &remaining[..write_len];
            self.send_without_response(Command::ProgramAppend, address, write_len as u32, chunk)?;
            // std::thread::sleep(Duration::from_millis(1));

            remaining = &remaining[write_len..];
            address = address.wrapping_add(write_len as u32);
            pos_in_page += write_len;

            if pos_in_page == FLUSH_PAGE_SIZE || remaining.is_empty() {
                println!("Program address: 0x{address:08x}");
                self.send(Command::Flush, 0, 0, &[], TIMEOUT.mul_f64(64.0))?;
                pos_in_page = 0;
            }
        }

        self.send(Command::Flush, 0, 0, &[], TIMEOUT.mul_f64(32.0))?;

        println!("OK.");
        Ok(())
    }

    fn erase(&self, start_address: u32, size: usize) -> Result<()> {
        if start_address % FLUSH_PAGE_SIZE as u32 != 0 || size % FLUSH_PAGE_SIZE != 0 {
            bail!("erase requires address and size to be 4096-byte aligned");
        }

        let mut address = start_address;
        let mut remaining = size;
        while remaining > 0 {
            let resp = self.send(
                Command::Erase,
                address,
                FLUSH_PAGE_SIZE as u32,
                &[],
                TIMEOUT.mul_f64((size / 1024) as f64),
            )?;
            if resp.get(0).copied().unwrap_or(0) != 0x01 {
                bail!("Erase failed (addr=0x{address:08x})");
            }
            address = address.wrapping_add(FLUSH_PAGE_SIZE as u32);
            remaining -= FLUSH_PAGE_SIZE;
        }
        Ok(())
    }

    fn read(&self, start_address: u32, size: usize) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(size);

        while data.len() < size {
            let address = start_address.wrapping_add(data.len() as u32);
            let want = (size - data.len()).min(READ_BLOCK_SIZE);
            let resp = self.send(Command::Read, address, want as u32, &[], TIMEOUT)?;

            if resp.get(0).copied().unwrap_or(0) != 0x01 {
                bail!("Read failed (addr=0x{address:08x})");
            }

            // The device silently clamps the request, so trust the length it
            // reports rather than the length we asked for.
            let got = *resp.get(1).unwrap_or(&0) as usize;
            if got == 0 {
                bail!("READ returned no data (addr=0x{address:08x})");
            }
            let end = got.saturating_add(2).min(resp.len());
            data.extend_from_slice(&resp[2..end]);

            if end < got + 2 {
                bail!("READ response was truncated (addr=0x{address:08x})");
            }
        }

        data.truncate(size);
        Ok(data)
    }

    fn crc(&self, start_address: u32, size: u32) -> Result<u16> {
        let timeout = TIMEOUT.mul_f64((size as f64 / 1024.0).max(1.0));
        let resp = self.send(Command::Crc, start_address, size, &[], timeout)?;
        Ok(u16::from_le_bytes([
            resp.get(2).copied().unwrap_or(0),
            resp.get(3).copied().unwrap_or(0),
        ]))
    }

    fn verify(&self, start_address: u32, data: &[u8]) -> Result<bool> {
        let expected = crc16_ccitt(data);
        let actual = self.crc(start_address, data.len() as u32)?;
        Ok(expected == actual)
    }

    fn reset(&self) {
        let _resp = self.send(Command::Reset, 0, 0, &[], TIMEOUT);
    }

    /// Resets into the bootloader instead of the application.
    ///
    /// Like `reset`, the device reboots before answering, so there is no
    /// response to wait for and a failure here is not an error.
    fn reset_bootloader(&self) {
        let _resp = self.send(Command::ResetBootloader, 0, 0, &[], TIMEOUT);
    }

    fn send(
        &self,
        command: Command,
        param1: u32,
        param2: u32,
        data: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        self.transport.send(command, param1, param2, data, timeout)
    }

    fn send_without_response(&self, command: Command, param1: u32, param2: u32, data: &[u8]) -> Result<()> {
        self.transport
            .send_without_response(command, param1, param2, data)
    }
}

mod nusb_transport {
    use super::*;
    use anyhow::Error;
    use futures_lite::future::block_on;
    use nusb::transfer::{Direction, EndpointType, RequestBuffer};

    pub struct NusbTransport {
        interface: nusb::Interface,
        endpoint_in: u8,
        endpoint_out: u8,
    }

    /// Enumerates matching devices without opening any of them.
    ///
    /// Seeing more than one is a valid result here — this is the diagnostic for
    /// the multiple-match abort, so it neither retries nor fails on a duplicate.
    pub fn list_devices(vid: u16, pid: u16) -> Result<()> {
        let devices: Vec<nusb::DeviceInfo> = nusb::list_devices()
            .context("NUSB list_devices failed")?
            .filter(|dev| dev.vendor_id() == vid && dev.product_id() == pid)
            .collect();

        println!("Device: vid=0x{vid:04x} pid=0x{pid:04x}");
        if devices.is_empty() {
            println!("No matching device.");
        } else {
            log_device_candidates(&devices);
        }
        Ok(())
    }

    /// Marks the "two boards are plugged in" case, which retrying cannot resolve.
    #[derive(Debug)]
    pub struct MultipleDevices {
        pub vid: u16,
        pub pid: u16,
        pub count: usize,
    }

    impl std::fmt::Display for MultipleDevices {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let Self { vid, pid, count } = self;
            write!(
                f,
                "multiple matching USB devices found (vid=0x{vid:04x} pid=0x{pid:04x} count={count})"
            )
        }
    }

    impl std::error::Error for MultipleDevices {}

    impl NusbTransport {
        /// `verbose` gates the per-device diagnostics so a retry loop does not
        /// repeat the candidate dump on every attempt.
        pub fn open(vid: u16, pid: u16, verbose: bool) -> Result<Self> {
            let devices: Vec<nusb::DeviceInfo> = nusb::list_devices()
                .context("NUSB list_devices failed")?
                .filter(|dev| dev.vendor_id() == vid && dev.product_id() == pid)
                .collect();

            if devices.is_empty() {
                bail!("NUSB device not found");
            }

            if verbose || devices.len() > 1 {
                log_device_candidates(&devices);
            }

            if devices.len() > 1 {
                return Err(Error::new(MultipleDevices {
                    vid,
                    pid,
                    count: devices.len(),
                }));
            }

            let mut preferred = Vec::with_capacity(devices.len());
            // let mut fallback = Vec::new();
            preferred.extend(devices);
            // for dev in devices {
            //     if is_winusb_driver(&dev) {
            //         preferred.push(dev);
            //     } else {
            //         fallback.push(dev);
            //     }
            // }
            // preferred.extend(fallback);

            let mut last_err = None;
            for device_info in preferred {
                if verbose {
                    log_device_attempt(&device_info);
                }
                let result = try_open_device(&device_info, verbose);
                match result {
                    Ok(transport) => return Ok(transport),
                    Err(err) => last_err = Some(err),
                }
            }

            Err(last_err.unwrap_or_else(|| anyhow::anyhow!("NUSB open failed")))
        }
    }

    impl BootTransport for NusbTransport {
        fn send(
            &self,
            command: Command,
            param1: u32,
            param2: u32,
            data: &[u8],
            _timeout: Duration,
        ) -> Result<Vec<u8>> {
            let payload = build_payload(command, param1, param2, data);

            let completion = block_on(self.interface.bulk_out(self.endpoint_out, payload))
                .into_result()
                .context("NUSB write failed")?;
            if completion.actual_length() != PACKET_SIZE {
                bail!("NUSB write size mismatch ({} bytes)", completion.actual_length());
            }

            for _ in 0..8 {
                let resp =
                    block_on(self.interface.bulk_in(self.endpoint_in, RequestBuffer::new(PACKET_SIZE)))
                        .into_result()
                        .context("NUSB read failed")?;
                if resp.len() != PACKET_SIZE {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                } else {
                    return Ok(resp);
                }
            }
            Err(Error::msg("no response"))
            // Ok(resp)
        }

        fn send_without_response(
            &self,
            command: Command,
            param1: u32,
            param2: u32,
            data: &[u8],
        ) -> Result<()> {
            let payload = build_payload(command, param1, param2, data);
            let completion = block_on(self.interface.bulk_out(self.endpoint_out, payload))
                .into_result()
                .context("NUSB write failed")?;
            if completion.actual_length() != PACKET_SIZE {
                bail!("NUSB write size mismatch ({} bytes)", completion.actual_length());
            }
            Ok(())
        }

        fn kind(&self) -> &'static str {
            "NUSB"
        }
    }

    fn try_open_device(device_info: &nusb::DeviceInfo, verbose: bool) -> Result<NusbTransport> {
        let device = device_info.open().context("NUSB open failed")?;
        let config = device
            .active_configuration()
            .context("NUSB active configuration failed")?;
        let (interface_number, alt_setting, endpoint_in, endpoint_out) =
            find_vendor_bulk_interface(&config)
                .context("Vendor bulk endpoints not found")?;
        if verbose {
            eprintln!(
                "NUSB select interface={} alt={} in=0x{:02x} out=0x{:02x}",
                interface_number, alt_setting, endpoint_in, endpoint_out
            );
        }

        let interface = device
            .claim_interface(interface_number)
            .with_context(|| format!("NUSB claim interface {interface_number} failed"))?;
        if alt_setting != 0 {
            interface
                .set_alt_setting(alt_setting)
                .with_context(|| format!("NUSB set alt setting {alt_setting} failed"))?;
        }

        Ok(NusbTransport {
            interface,
            endpoint_in,
            endpoint_out,
        })
    }

    fn find_vendor_bulk_interface(
        config: &nusb::descriptors::Configuration<'_>,
    ) -> Option<(u8, u8, u8, u8)> {
        let mut best = None;

        for interface in config.interfaces() {
            for alt in interface.alt_settings() {
                let mut endpoint_in = None;
                let mut endpoint_out = None;
                for endpoint in alt.endpoints() {
                    if endpoint.transfer_type() != EndpointType::Bulk {
                        continue;
                    }
                    match endpoint.direction() {
                        Direction::In => {
                            if endpoint_in.is_none() {
                                endpoint_in = Some(endpoint.address());
                            }
                        }
                        Direction::Out => {
                            if endpoint_out.is_none() {
                                endpoint_out = Some(endpoint.address());
                            }
                        }
                    }
                }

                if let (Some(in_ep), Some(out_ep)) = (endpoint_in, endpoint_out) {
                    let candidate = (
                        interface.interface_number(),
                        alt.alternate_setting(),
                        in_ep,
                        out_ep,
                    );
                    if alt.class() == 0xFF {
                        return Some(candidate);
                    }
                    if best.is_none() {
                        best = Some(candidate);
                    }
                }
            }
        }
        best
    }

    fn log_device_candidates(devices: &[nusb::DeviceInfo]) {
        eprintln!("NUSB candidates: {}", devices.len());
        for (idx, dev) in devices.iter().enumerate() {
            #[cfg(target_os = "windows")]
            {
                eprintln!(
                    "  [{}] driver={:?} instance_id={:?}",
                    idx,
                    dev.driver(),
                    dev.instance_id()
                );
            }
            #[cfg(not(target_os = "windows"))]
            {
                eprintln!("  [{}] device", idx);
            }

            let mut interfaces = dev.interfaces().peekable();
            if interfaces.peek().is_none() {
                eprintln!("      interfaces: <none>");
            } else {
                for iface in interfaces {
                    eprintln!(
                        "      interface {} class=0x{:02x} subclass=0x{:02x} protocol=0x{:02x}",
                        iface.interface_number(),
                        iface.class(),
                        iface.subclass(),
                        iface.protocol()
                    );
                }
            }
        }
    }

    fn log_device_attempt(dev: &nusb::DeviceInfo) {
        #[cfg(target_os = "windows")]
        {
            eprintln!(
                "NUSB try: driver={:?} instance_id={:?}",
                dev.driver(),
                dev.instance_id()
            );
        }
        #[cfg(not(target_os = "windows"))]
        {
            eprintln!("NUSB try device");
        }
    }
}

fn build_payload(command: Command, param1: u32, param2: u32, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PACKET_SIZE);
    payload.push(command as u8);
    payload.extend_from_slice(&param1.to_le_bytes());
    payload.extend_from_slice(&param2.to_le_bytes());
    payload.extend_from_slice(data);
    payload.resize(PACKET_SIZE, 0);
    payload
}

fn parse_u64(input: &str) -> Result<u64, String> {
    let (radix, digits) = if let Some(rest) = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")) {
        (16, rest)
    } else if let Some(rest) = input.strip_prefix("0b").or_else(|| input.strip_prefix("0B")) {
        (2, rest)
    } else if let Some(rest) = input.strip_prefix("0o").or_else(|| input.strip_prefix("0O")) {
        (8, rest)
    } else {
        (10, input)
    };

    u64::from_str_radix(digits, radix)
        .map_err(|e| format!("invalid number ({input}): {e}"))
}

fn parse_u32(input: &str) -> Result<u32, String> {
    parse_u64(input).and_then(|v| u32::try_from(v).map_err(|_| format!("number too large ({input})")))
}

fn parse_u16(input: &str) -> Result<u16, String> {
    parse_u64(input).and_then(|v| u16::try_from(v).map_err(|_| format!("number too large ({input})")))
}

fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    let poly: u16 = 0x1021;

    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ poly;
            } else {
                crc <<= 1;
            }
        }
    }

    crc
}

fn erase_range(start_address: u32, size: usize) -> Result<(u32, usize)> {
    let erase_start = start_address & !((FLUSH_PAGE_SIZE as u32) - 1);
    let end_address = start_address
        .checked_add(u32::try_from(size).context("firmware size exceeds 32-bit address space")?)
        .context("erase end address overflow")?;
    let erase_end = end_address
        .checked_add((FLUSH_PAGE_SIZE as u32) - 1)
        .context("erase end address overflow")?
        & !((FLUSH_PAGE_SIZE as u32) - 1);
    let erase_size = usize::try_from(erase_end - erase_start).context("erase range too large")?;
    Ok((erase_start, erase_size))
}

/// Refuses an operation that would touch a region listed in `PROTECTED_REGIONS`.
///
/// The device answers a misaligned or out-of-range erase with RESP_OK and
/// silently does nothing, so this host-side check is the only guard there is.
fn check_protected(start_address: u32, size: u32, op: &str) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    let end = start_address
        .checked_add(size)
        .context("address + size overflow")?;

    for &(base, len, name) in PROTECTED_REGIONS {
        let region_end = base + len;
        if start_address < region_end && base < end {
            bail!(
                "refusing to {op} 0x{start_address:08x}..0x{end:08x}: \
                 overlaps {name} (0x{base:08x}..0x{region_end:08x})"
            );
        }
    }
    Ok(())
}

/// Errors that retrying cannot resolve, so the loop must give up at once.
/// Two boards on the same VID/PID stay two boards no matter how long we wait.
fn is_fatal_open_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<nusb_transport::MultipleDevices>()
        .is_some()
}

fn open_transport(cli: &Cli) -> Result<Box<dyn BootTransport>> {
    let interval = Duration::from_millis(u64::from(cli.retry_interval));
    let mut attempt: u32 = 0;

    loop {
        // Only the first attempt prints the per-device diagnostics, so a long
        // retry run stays readable.
        match nusb_transport::NusbTransport::open(cli.vid, cli.pid, attempt == 0) {
            Ok(transport) => return Ok(Box::new(transport)),
            Err(err) => {
                if is_fatal_open_error(&err) {
                    return Err(err);
                }
                if attempt >= cli.retries {
                    return Err(if cli.retries == 0 {
                        err
                    } else {
                        err.context(format!(
                            "timed out waiting for target USB device ({} attempts, {} ms interval)",
                            cli.retries + 1,
                            cli.retry_interval
                        ))
                    });
                }
                attempt += 1;
                eprintln!("Waiting for device... (retry {attempt}/{})", cli.retries);
                std::thread::sleep(interval);
            }
        }
    }
}

/// Reads a firmware file and works out where it will land.
fn load_firmware(bin: &PathBuf, address: u32, offset: u32) -> Result<(Vec<u8>, u32)> {
    let start_address = address
        .checked_add(offset)
        .context("address + offset overflow")?;

    let firmware =
        fs::read(bin).with_context(|| format!("failed to read firmware: {}", bin.display()))?;

    if firmware.is_empty() {
        bail!("firmware is empty: {}", bin.display());
    }

    Ok((firmware, start_address))
}

/// Announces the target, opens it (retrying per the global options) and reads IDENT.
fn connect(cli: &Cli) -> Result<Bootloader> {
    println!(
        "Device: vid=0x{vid:04x} pid=0x{pid:04x}",
        vid = cli.vid,
        pid = cli.pid
    );

    let transport = open_transport(cli)?;
    let boot = Bootloader::new(transport);
    println!("Transport: {}", boot.transport_kind());
    let ident = boot.get_ident()?;
    println!("Ident: {ident}");
    Ok(boot)
}

fn cmd_flash(cli: &Cli, args: &FlashArgs) -> Result<()> {
    let (firmware, start_address) = load_firmware(&args.bin, args.address, args.offset)?;
    let (erase_start, erase_size) = erase_range(start_address, firmware.len())?;

    // Check before opening the device so a refused write costs nothing, and
    // check the widened erase range too since it can reach further than the
    // firmware itself.
    check_protected(start_address, firmware.len() as u32, "write")?;
    check_protected(erase_start, erase_size as u32, "erase")?;

    let boot = connect(cli)?;

    println!(
        "Erase: addr=0x{start:08x} size={size} ({} KB)",
        erase_size / 1024,
        start = erase_start,
        size = erase_size
    );
    boot.erase(erase_start, erase_size)?;

    println!(
        "Program: addr=0x{start:08x} size={} bytes",
        firmware.len(),
        start = start_address
    );
    boot.write(start_address, &firmware)?;
    println!("Write done.");

    if args.verify {
        println!("CRC16 verify...");
        if boot.verify(start_address, &firmware)? {
            println!("Verify OK");
        } else {
            bail!("Verify NG (CRC mismatch)");
        }
    }

    if args.no_reset {
        println!("Leaving device in the bootloader.");
    } else {
        println!("Resetting device...");
        boot.reset();
    }

    Ok(())
}

fn cmd_erase(cli: &Cli, args: &EraseArgs) -> Result<()> {
    let page = FLUSH_PAGE_SIZE as u32;
    if args.address % page != 0 || args.size % page != 0 {
        // Do not widen the range on the user's behalf: they named it, and the
        // device would report success while erasing nothing.
        let (aligned_start, aligned_size) = erase_range(args.address, args.size as usize)?;
        bail!(
            "erase requires address and size to be {page}-byte aligned \
             (try --address 0x{aligned_start:08x} --size 0x{aligned_size:x})"
        );
    }
    check_protected(args.address, args.size, "erase")?;

    let boot = connect(cli)?;
    println!(
        "Erase: addr=0x{start:08x} size={size} ({} KB)",
        args.size / 1024,
        start = args.address,
        size = args.size
    );
    boot.erase(args.address, args.size as usize)?;
    println!("Erase done.");
    Ok(())
}

fn cmd_read(cli: &Cli, args: &ReadArgs) -> Result<()> {
    if args.size == 0 {
        bail!("--size must be greater than 0");
    }

    let boot = connect(cli)?;
    println!(
        "Read: addr=0x{start:08x} size={size} bytes",
        start = args.address,
        size = args.size
    );
    let data = boot.read(args.address, args.size as usize)?;

    fs::write(&args.out, &data)
        .with_context(|| format!("failed to write output: {}", args.out.display()))?;
    println!("Wrote {} bytes to {}", data.len(), args.out.display());
    Ok(())
}

fn cmd_verify(cli: &Cli, args: &VerifyArgs) -> Result<()> {
    let (firmware, start_address) = load_firmware(&args.bin, args.address, args.offset)?;

    let boot = connect(cli)?;
    println!(
        "Verify: addr=0x{start:08x} size={} bytes",
        firmware.len(),
        start = start_address
    );
    if boot.verify(start_address, &firmware)? {
        println!("Verify OK");
        Ok(())
    } else {
        bail!("Verify NG (CRC mismatch)");
    }
}

fn cmd_crc(cli: &Cli, args: &CrcArgs) -> Result<()> {
    let boot = connect(cli)?;
    let crc = boot.crc(args.address, args.size)?;
    println!(
        "CRC16: 0x{crc:04x} (addr=0x{start:08x} size={size})",
        start = args.address,
        size = args.size
    );
    Ok(())
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Flash(args) => cmd_flash(&cli, args),
        Commands::Erase(args) => cmd_erase(&cli, args),
        Commands::Read(args) => cmd_read(&cli, args),
        Commands::Verify(args) => cmd_verify(&cli, args),
        Commands::Crc(args) => cmd_crc(&cli, args),
        Commands::Probe => {
            connect(&cli)?;
            Ok(())
        }
        Commands::Reset => {
            let boot = connect(&cli)?;
            println!("Resetting device...");
            boot.reset();
            Ok(())
        }
        Commands::ResetBootloader => {
            let boot = connect(&cli)?;
            println!("Resetting into the bootloader...");
            boot.reset_bootloader();
            Ok(())
        }
        Commands::List => nusb_transport::list_devices(cli.vid, cli.pid),
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{check_protected, is_fatal_open_error, nusb_transport::MultipleDevices};

    /// The device reports success for an erase it silently skipped, so this
    /// check is the only thing standing between a typo and a bricked board.
    #[test]
    fn protected_regions_are_refused() {
        // Whole region, and the 0x0000_0000 alias of the same flash.
        assert!(check_protected(0x0800_0000, 0x1000, "erase").is_err());
        assert!(check_protected(0x0000_0000, 0x1000, "erase").is_err());
        assert!(check_protected(0x1fff_8000, 0x1000, "erase").is_err());

        // Partial overlaps from either side must be caught, not just containment.
        assert!(check_protected(0x0800_3000, 0x2000, "erase").is_err());
        assert!(check_protected(0x0800_3fff, 1, "write").is_err());
    }

    #[test]
    fn addresses_outside_protected_regions_are_allowed() {
        // First byte past the bootloader: the boundary itself must be usable.
        assert!(check_protected(0x0800_4000, 0x1000, "erase").is_ok());
        assert!(check_protected(0x0000_4000, 0x1000, "erase").is_ok());
        // Butting up against the start of a region from below.
        assert!(check_protected(0x1fff_7000, 0x1000, "erase").is_ok());
        // A zero-length range overlaps nothing.
        assert!(check_protected(0x0800_0000, 0, "write").is_ok());
    }

    /// The retry loop stops on this error instead of waiting out the full count.
    #[test]
    fn multiple_devices_is_fatal_but_a_missing_device_is_not() {
        let multiple = anyhow::Error::new(MultipleDevices {
            vid: 0xf055,
            pid: 0x6585,
            count: 2,
        });
        assert!(is_fatal_open_error(&multiple));

        // The ordinary "not there yet" case must stay retryable, including once
        // it has been wrapped by the timeout context.
        let missing = anyhow::anyhow!("NUSB device not found");
        assert!(!is_fatal_open_error(&missing));
        assert!(!is_fatal_open_error(&missing.context("timed out")));
    }

    /// `main()` prints `Error: {err:?}`; this pins the `{err:?}` half, which must
    /// stay identical to the message the old `bail!` produced.
    #[test]
    fn multiple_devices_keeps_its_message() {
        let err = anyhow::Error::new(MultipleDevices {
            vid: 0xf055,
            pid: 0x6585,
            count: 2,
        });
        assert_eq!(
            format!("{err:?}"),
            "multiple matching USB devices found (vid=0xf055 pid=0x6585 count=2)"
        );
    }
}
