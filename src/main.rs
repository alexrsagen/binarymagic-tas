mod sigscan;
mod sys;
use sys::{
    attach_window_input, dump_process_memory, find_window_by_pid, send_window_keycodes,
    send_window_scancodes,
};

use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Input::KeyboardAndMouse::{VK_DOWN, VK_RETURN};

fn sc_for_bitval(bitval: u8) -> Option<u16> {
    match bitval {
        0b10000000 => Some(SC_1),
        0b01000000 => Some(SC_2),
        0b00100000 => Some(SC_3),
        0b00010000 => Some(SC_4),
        0b00001000 => Some(SC_5),
        0b00000100 => Some(SC_6),
        0b00000010 => Some(SC_7),
        0b00000001 => Some(SC_8),
        _ => None,
    }
}

const SC_1: u16 = 2;
const SC_2: u16 = 3;
const SC_3: u16 = 4;
const SC_4: u16 = 5;
const SC_5: u16 = 6;
const SC_6: u16 = 7;
const SC_7: u16 = 8;
const SC_8: u16 = 9;
const SC_SPACE: u16 = 57;

fn sc_seq_for_number(number: u8, last_number: &mut u8) -> (bool, Vec<u16>) {
    // last number is equal to number, flip a bit!
    if number == *last_number {
        return (true, vec![SC_1, SC_1]);
    }

    let reset_key_count = if *last_number == 0 { 0 } else { 1 };
    let diff = number ^ *last_number;

    let mut bitvals_number = Vec::new();
    let mut bitvals_diff = Vec::new();
    for i in 0..u8::BITS as u8 {
        let bitval = 1 << i;
        if number & bitval == bitval {
            bitvals_number.push(bitval);
        }
        if diff & bitval == bitval {
            bitvals_diff.push(bitval);
        }
    }

    let mut keys = Vec::new();
    if bitvals_number.len() + reset_key_count < bitvals_diff.len() {
        keys.push(SC_SPACE);
        for bitval in bitvals_number {
            if let Some(key) = sc_for_bitval(bitval) {
                keys.push(key);
            }
        }
    } else {
        for bitval in bitvals_diff {
            if let Some(key) = sc_for_bitval(bitval) {
                keys.push(key);
            }
        }
    }

    // last number is not equal to number, but we still have 0 keys?
    if keys.len() == 0 {
        eprintln!(
            "[!] something is very wrong. last number: {}, new number: {}",
            *last_number, number
        );
    }

    *last_number = number;
    (false, keys)
}

#[test]
fn test_sc_seq_0xff_0xff() {
    let mut last_number = 0xFF;
    assert_eq!(
        sc_seq_for_number(0xFF, &mut last_number),
        (true, vec![SC_1, SC_1])
    );
    assert_eq!(last_number, 0xFF);
}

#[test]
fn test_sc_seq_0x82_0xff() {
    let mut last_number = 0x82;
    assert_eq!(
        sc_seq_for_number(0xFF, &mut last_number),
        (false, vec![SC_8, SC_6, SC_5, SC_4, SC_3, SC_2])
    );
    assert_eq!(last_number, 0xFF);
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum NumberType {
    Charge = 0,
    NormalOrDrain = 1,
    // TODO: Detect difference between Normal and Drain numbers
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Number {
    number_type: NumberType,
    number: u8,
    is_hex: bool,
}

impl std::fmt::Display for Number {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_hex {
            write!(f, "0x{:02X} ({:?})", self.number, self.number_type)
        } else {
            write!(f, "{} ({:?})", self.number, self.number_type)
        }
    }
}

const BASE_SIGNATURE: &'static str = "
?? ?? 00 00 00 00 00 00 01 00 00 00 ?? 00 00 00
18 00 00 00 ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 00 00
?? ?? ?? ?? ?? ?? 00 00 02 00 00 00 ?? ?? ?? ??
?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
01 00 00 00 ?? ?? ?? ?? ?? 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 02 00 00 00 ?? ?? ?? ??
?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
";

const IS_HEX_SIGNATURE: &'static str = "
?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ??
?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
";

const CHARGE_SIGNATURE: &'static str = "
00 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 06 ?? ?? ??
?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
";

const GRACE_PERIOD_SOLVES: usize = 5;
const PRESSURE_INCREASE_STEP: usize = 25;
const PRESSURE_STEP: f64 = 0.75;
const MAX_HEAT: usize = 100;
const HEAT_INTERVAL: Duration = Duration::from_millis(150);

fn main() {
    use std::process::exit;

    let key_hold_time = Duration::from_millis(12);

    let base_signature: sigscan::Signature = match BASE_SIGNATURE.parse() {
        Ok(signature) => signature,
        Err(e) => {
            eprintln!("[-] unable to parse signature: {}", e);
            exit(1);
        }
    };

    let is_hex_signature: sigscan::Signature = match IS_HEX_SIGNATURE.parse() {
        Ok(signature) => signature,
        Err(e) => {
            eprintln!("[-] unable to parse signature: {}", e);
            exit(1);
        }
    };

    let charge_signature: sigscan::Signature = match CHARGE_SIGNATURE.parse() {
        Ok(signature) => signature,
        Err(e) => {
            eprintln!("[-] unable to parse signature: {}", e);
            exit(1);
        }
    };

    let child = match Command::new("BinaryMagic.exe").spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("[-] unable to spawn process: {}", e);
            exit(1);
        }
    };
    let pid = child.id();
    eprintln!("[+] spawned process ID {}", pid);

    eprintln!("[*] looking for window...");
    let mut window_handle = HWND(0);
    for _attempt in 0..10 {
        match find_window_by_pid(pid) {
            Ok(handle) => {
                window_handle = handle;
                break;
            }
            Err(_e) => {}
        };
        sleep(Duration::from_millis(500));
    }
    if window_handle == HWND(0) {
        eprintln!("[-] could not find window");
        exit(1);
    }
    eprintln!("[+] found window");

    match attach_window_input(window_handle) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("[-] unable to attach thread input: {}", e);
            exit(1);
        }
    };
    eprintln!("[+] attached thread input");

    // Go down from Story Mode to Endless Mode, select option:
    // ------------
    // > Story Mode
    // Endless Mode
    // Quit
    // ------------
    std::thread::sleep(Duration::from_secs(4));
    match send_window_keycodes(window_handle, &[VK_DOWN, VK_RETURN], key_hold_time) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("[-] unable to navigate to endless mode: {}", e);
            exit(1);
        }
    };
    eprintln!("[+] navigated to endless mode");

    // Go up from Hex and Decimal to Hexadecimal, select option:
    // -----------------
    // Hexadecimal
    // Decimal
    // > Hex and Decimal
    // -----------------
    std::thread::sleep(Duration::from_millis(1250));
    match send_window_keycodes(window_handle, &[VK_RETURN], key_hold_time) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("[-] unable to navigate to endless mode: {}", e);
            exit(1);
        }
    };
    eprintln!("[+] navigated to hex and decimal");

    // wait for hax time...
    std::thread::sleep(Duration::from_millis(7000));

    // hax time!
    let mut solves = 0usize;
    let mut heat = 0usize;
    let mut pressure = 1.0f64;
    let mut instant_spawn = false;
    let mut last_number = 0u8;
    let mut last_input_time = Instant::now();
    loop {
        let dump = match dump_process_memory(pid, None) {
            Ok(dump) => dump,
            Err(e) => {
                eprintln!("[-] unable to dump process memory: {}", e);
                exit(1);
            }
        };

        let mut numbers = Vec::new();
        let signature_matches = base_signature.scan_dump(&dump, None);
        for signature_match in signature_matches {
            let signature_data = signature_match.data();
            let is_hex = is_hex_signature.match_bytes(signature_data);
            let number_type = if charge_signature.match_bytes(signature_data) {
                NumberType::Charge
            } else {
                NumberType::NormalOrDrain
            };
            let number = u64::from_le_bytes([
                signature_data[0x30],
                signature_data[0x31],
                signature_data[0x32],
                signature_data[0x33],
                signature_data[0x34],
                signature_data[0x35],
                signature_data[0x36],
                signature_data[0x37],
            ]) as u8;
            numbers.push(Number {
                number_type,
                number,
                is_hex,
            });
        }

        numbers.sort();
        for (i, number) in numbers.iter().enumerate() {
            eprintln!("[+] {}/{}: {}", i + 1, numbers.len(), number);

            // get scancode sequence for number to input
            let (extra_hold_time, scancodes) = sc_seq_for_number(number.number, &mut last_number);
            let hold_time = if extra_hold_time {
                key_hold_time * 2
            } else {
                key_hold_time
            };

            if scancodes.len() > 0 {
                // wait for heat meter to cool down just enough to input scancodes
                let time_since_last_input = Instant::now().duration_since(last_input_time);
                let heat_amount_since_last_input = (time_since_last_input.as_millis() as f64
                    / HEAT_INTERVAL.as_millis() as f64)
                    .floor() as usize;
                let mut new_heat_meter_value =
                    heat.saturating_sub(heat_amount_since_last_input) + scancodes.len();
                if new_heat_meter_value >= MAX_HEAT {
                    let wait_amount = new_heat_meter_value.saturating_sub(MAX_HEAT);
                    if wait_amount > 0 {
                        let wait_time = HEAT_INTERVAL * wait_amount as u32;
                        if !wait_time.is_zero() {
                            std::thread::sleep(wait_time);
                        }
                        new_heat_meter_value -= wait_amount;
                    }
                }

                match send_window_scancodes(window_handle, &scancodes, hold_time) {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("[-] unable to input number: {}", e);
                        exit(1);
                    }
                };

                // increase heat meter value
                heat = new_heat_meter_value;
                last_input_time = Instant::now();

                // wait for game to register input
                // std::thread::sleep(key_hold_time);

                // track instant spawn and pressure
                solves += 1;
                if solves % PRESSURE_INCREASE_STEP == 0 && solves > GRACE_PERIOD_SOLVES {
                    if pressure < 9.0 {
                        pressure += PRESSURE_STEP;
                        eprintln!("[*] pressure increased to {}", pressure);
                    }
                }
                if solves == 200 {
                    eprintln!("[*] instant spawn mode enabled");
                    instant_spawn = true;
                }
            }
        }
    }
}
