use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use hidapi::{HidApi, HidDevice};

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
enum Command {
    Nop = 0,
    Ident = 1,
    Erase = 2,
    ProgramStart = 3,
    ProgramAppend = 4,
    Flush = 5,
    Read = 6,
    Reset = 7,
    Crc = 8
}

const TIMEOUT: Duration = Duration::from_millis(100);
const READ_BLOCK_SIZE: usize = 62;
const WRITE_BLOCK_SIZE: usize = 54;
const FLUSH_PAGE_SIZE: usize = 4096;

#[derive(Debug, Parser)]
#[command(author, version, about = "HIDブートローダー用アップローダー")]
struct Cli {
    /// 書き込むバイナリファイルパス
    #[arg(long, value_name = "PATH")]
    bin: PathBuf,
    /// ベースアドレス（例: 0x08000000）
    #[arg(long, value_parser = parse_u32, value_name = "ADDR")]
    address: u32,
    /// ベースアドレスに足すオフセット
    #[arg(long, default_value = "0", value_parser = parse_u32, value_name = "OFFSET")]
    offset: u32,
    /// VID (例: 0xf055)
    #[arg(long, default_value = "0xf055", value_parser = parse_u16, value_name = "VID")]
    vid: u16,
    /// PID (例: 0x6585)
    #[arg(long, default_value = "0x6585", value_parser = parse_u16, value_name = "PID")]
    pid: u16,
    /// Product String が一致するか確認する。空文字ならチェックしない。
    #[arg(long, default_value = "HID Bootloader", value_name = "NAME")]
    product: String,
    /// 書き込み前にページ単位で消去する
    #[arg(long, default_value_t = false)]
    erase: bool,
    /// 書き込み後にCRC16で検証する
    #[arg(long, default_value_t = false)]
    verify: bool,
}

struct HidBootloader<'a> {
    device: &'a HidDevice,
}

impl<'a> HidBootloader<'a> {
    fn new(device: &'a HidDevice) -> Self {
        Self { device }
    }

    fn get_ident(&self) -> Result<String> {
        let resp = self.send(Command::Ident, 0, 0, &[], TIMEOUT)?;
        let len = *resp.get(1).unwrap_or(&0) as usize;
        let end = len.saturating_add(2).min(resp.len());
        let text = std::str::from_utf8(&resp[2..end]).context("IDENT応答の文字列が不正です")?;
        Ok(text.to_string())
    }

    fn read(&self, start_address: u32, size: usize) -> Result<Vec<u8>> {
        let mut remaining = size;
        let mut address = start_address;
        let mut data = Vec::with_capacity(size);

        while remaining > 0 {
            let read_len = remaining.min(READ_BLOCK_SIZE) as u32;
            let resp = self.send(Command::Read, address, read_len, &[], TIMEOUT)?;
            let payload_len = usize::min(
                *resp.get(1).unwrap_or(&0) as usize,
                resp.len().saturating_sub(2),
            );
            data.extend_from_slice(&resp[2..2 + payload_len]);
            address = address.wrapping_add(read_len);
            remaining -= read_len as usize;
        }

        Ok(data)
    }

    fn write(&self, start_address: u32, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut remaining = data;
        let mut address = start_address;
        let mut pos_in_page: usize = 0;

        while !remaining.is_empty() {
            if pos_in_page == 0 {
                println!("Program Start");
                self.send_without_response(Command::ProgramStart, address, 0, &[])?;
            }

            let mut write_len = remaining.len().min(WRITE_BLOCK_SIZE);
            if pos_in_page + write_len > FLUSH_PAGE_SIZE {
                write_len = FLUSH_PAGE_SIZE - pos_in_page;
            }

            let chunk = &remaining[..write_len];
            // println!("ProgramAppend {address}, {write_len}");
            self.send_without_response(Command::ProgramAppend, address, write_len as u32, chunk)?;

            remaining = &remaining[write_len..];
            address = address.wrapping_add(write_len as u32);
            pos_in_page += write_len;

            if pos_in_page == FLUSH_PAGE_SIZE || remaining.len() == 0{
                print!("*");
                self.send(Command::Flush, 0, 0, &[], TIMEOUT.mul_f64(64.0))?;
                pos_in_page = 0;
            }
        }

        self.send(Command::Flush, 0, 0, &[], TIMEOUT.mul_f64(32.0))?;
        Ok(())
    }

    fn erase(&self, start_address: u32, size: usize) -> Result<()> {
        if start_address % FLUSH_PAGE_SIZE as u32 != 0 || size % FLUSH_PAGE_SIZE != 0 {
            bail!("eraseはアドレス/サイズが4096バイト境界に揃っている必要があります");
        }

        let mut address = start_address;
        let mut remaining = size;
        while remaining > 0 {
            let resp = self.send(Command::Erase, address, FLUSH_PAGE_SIZE as u32, &[], TIMEOUT.mul_f64((size / 1024) as f64))?;
            if resp.get(0).copied().unwrap_or(0) != 0x01 {
                bail!("Erase失敗 (addr=0x{address:08x})");
            }
            address = address.wrapping_add(FLUSH_PAGE_SIZE as u32);
            remaining -= FLUSH_PAGE_SIZE;
        }
        Ok(())
    }

    fn verify(&self, start_address: u32, data: &[u8]) -> Result<bool> {
        let expected = crc16_ccitt(data);
        let timeout = TIMEOUT.mul_f64((data.len() as f64 / 1024.0).max(1.0));
        let resp = self.send(Command::Crc, start_address, data.len() as u32, &[], timeout)?;
        let actual = u16::from_le_bytes([resp.get(2).copied().unwrap_or(0), resp.get(3).copied().unwrap_or(0)]);
        Ok(expected == actual)
    }

    fn reset(&self) {
        let _resp = self.send(Command::Reset, 0, 0, &[], TIMEOUT);
    }

    fn send(
        &self,
        command: Command,
        param1: u32,
        param2: u32,
        data: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(64);
        payload.push(command as u8);
        payload.extend_from_slice(&param1.to_le_bytes());
        payload.extend_from_slice(&param2.to_le_bytes());
        payload.extend_from_slice(data);
        payload.resize(64, 0);

        let mut packet = Vec::with_capacity(65);
        packet.push(0); // Report ID
        packet.extend_from_slice(&payload[..64]);
        self.device
            .write(&packet)
            .context("HID書き込みに失敗しました")?;

        let deadline = Instant::now() + timeout;
        let mut resp = vec![0u8; 64];

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout_ms = remaining.as_millis().clamp(1, i64::from(i32::MAX) as u128) as i32;
            let read_len = self
                .device
                .read_timeout(&mut resp, timeout_ms)
                .context("HID読み取りに失敗しました")?;
            if read_len == 64 {
                return Ok(resp);
            }
        }

        bail!("HID応答がタイムアウトしました");
    }

    fn send_without_response(&self, command: Command, param1: u32, param2: u32, data: &[u8]) -> Result<()> {
        let mut payload = Vec::with_capacity(64);
        payload.push(command as u8);
        payload.extend_from_slice(&param1.to_le_bytes());
        payload.extend_from_slice(&param2.to_le_bytes());
        payload.extend_from_slice(data);
        payload.resize(64, 0);

        let mut packet = Vec::with_capacity(65);
        packet.push(0);
        packet.extend_from_slice(&payload[..64]);
        self.device
            .write(&packet)
            .context("HID書き込みに失敗しました")?;
        Ok(())
    }
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

    u64::from_str_radix(digits, radix).map_err(|e| format!("数値を解釈できませんでした ({input}): {e}"))
}

fn parse_u32(input: &str) -> Result<u32, String> {
    parse_u64(input).and_then(|v| u32::try_from(v).map_err(|_| format!("値が大きすぎます ({input})")))
}

fn parse_u16(input: &str) -> Result<u16, String> {
    parse_u64(input).and_then(|v| u16::try_from(v).map_err(|_| format!("値が大きすぎます ({input})")))
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

fn run() -> Result<()> {
    let cli = Cli::parse();
    let start_address = cli
        .address
        .checked_add(cli.offset)
        .context("address + offset の計算でオーバーフローしました")?;

    let firmware = fs::read(&cli.bin)
        .with_context(|| format!("バイナリファイルを開けませんでした: {}", cli.bin.display()))?;

    if firmware.is_empty() {
        bail!("バイナリが空です: {}", cli.bin.display());
    }

    println!(
        "デバイス接続: vid=0x{vid:04x} pid=0x{pid:04x}",
        vid = cli.vid,
        pid = cli.pid
    );

    let api = HidApi::new().context("HID APIの初期化に失敗しました")?;
    let device = api
        .open(cli.vid, cli.pid)
        .context("指定VID/PIDのHIDデバイスを開けませんでした")?;

    if !cli.product.is_empty() {
        let product_string = device
            .get_product_string()
            .context("Product Stringの取得に失敗しました")?;
        if let Some(name) = product_string {
            if name != cli.product {
                bail!("ProductName不一致: デバイス=\"{name}\" / 期待=\"{}\"", cli.product);
            }
        } else {
            bail!("デバイスがProduct Stringを返しませんでした");
        }
    }

    let boot = HidBootloader::new(&device);
    let ident = boot.get_ident()?;
    println!("接続成功: {}", ident);

    if cli.erase {
        let erase_size = ((firmware.len() + FLUSH_PAGE_SIZE - 1) / FLUSH_PAGE_SIZE) * FLUSH_PAGE_SIZE;
        println!(
            "Erase: addr=0x{start:08x} size={size} ({} KB)",
            erase_size / 1024,
            start = start_address,
            size = erase_size
        );
        boot.erase(start_address, erase_size)?;
    }

    println!(
        "書き込み開始: addr=0x{start:08x} サイズ={} bytes",
        firmware.len(),
        start = start_address
    );
    boot.write(start_address, &firmware)?;
    println!("書き込み完了");

    if cli.verify {
        println!("CRC16検証中...");
        let ok = boot.verify(start_address, &firmware)?;
        if ok {
            println!("Verify OK");
        } else {
            bail!("Verify NG (CRC不一致)");
        }
    }

    println!("デバイスをリセットします");
    boot.reset();

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("エラー: {err:?}");
        std::process::exit(1);
    }
}
