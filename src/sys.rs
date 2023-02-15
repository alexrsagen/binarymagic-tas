use std::ffi::c_void;
use std::io::{Error, ErrorKind, Result};
use std::mem::size_of;
use std::mem::MaybeUninit;
use std::time::Duration;
use windows::Win32::Foundation::{BOOL, HANDLE, HWND, LPARAM};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_PROTECTION_FLAGS,
    PAGE_READWRITE, PAGE_TYPE, VIRTUAL_ALLOCATION_TYPE,
};
use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows::Win32::System::Threading::{
    AttachThreadInput, GetCurrentThreadId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP,
    KEYEVENTF_SCANCODE, VIRTUAL_KEY,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetMessageExtraInfo, GetWindow, GetWindowThreadProcessId, IsWindowVisible,
    SetForegroundWindow, GW_OWNER,
};

fn last_os_error<T>(input: T) -> Result<T> {
    let errno = Error::last_os_error();
    if errno.raw_os_error() == Some(0) {
        Ok(input)
    } else {
        Err(errno)
    }
}

fn bool_err(retval: BOOL) -> Result<()> {
    if retval.as_bool() {
        Ok(())
    } else {
        last_os_error(())
    }
}

fn u32_err(retval: u32) -> Result<u32> {
    if retval != 0 {
        Ok(retval)
    } else {
        last_os_error(retval)
    }
}

fn usize_err(retval: usize) -> Result<usize> {
    if retval != 0 {
        Ok(retval)
    } else {
        last_os_error(retval)
    }
}

#[derive(Default)]
struct EnumWindowsData {
    wanted_pid: u32,
    handle: HWND,
    found: bool,
}

unsafe extern "system" fn enum_windows_callback(handle: HWND, lparam: LPARAM) -> BOOL {
    let data = lparam.0 as *mut EnumWindowsData;
    let mut data = data.as_mut().unwrap();

    let mut pid = MaybeUninit::<u32>::zeroed();
    GetWindowThreadProcessId(handle, Some(pid.as_mut_ptr()));
    let pid = pid.assume_init();

    if pid == data.wanted_pid
        && GetWindow(handle, GW_OWNER).0 == 0
        && IsWindowVisible(handle).as_bool()
    {
        data.handle = handle;
        data.found = true;
        return BOOL(0);
    }

    BOOL(1)
}

pub fn find_window_by_pid(pid: u32) -> Result<HWND> {
    let mut data = MaybeUninit::new(EnumWindowsData {
        wanted_pid: pid,
        handle: HWND::default(),
        found: false,
    });
    let data = unsafe {
        bool_err(EnumWindows(
            Some(enum_windows_callback),
            LPARAM(data.as_mut_ptr() as isize),
        ))?;
        data.assume_init()
    };
    if !data.found {
        return Err(Error::new(
            ErrorKind::NotFound,
            "no window found matching pid",
        ));
    }
    Ok(data.handle)
}

fn message_extra_info() -> usize {
    unsafe { GetMessageExtraInfo().0 as usize }
}

pub fn attach_window_input(window: HWND) -> Result<()> {
    let our_tid = unsafe { GetCurrentThreadId() };
    let tid = unsafe { GetWindowThreadProcessId(window, None) };
    unsafe { bool_err(AttachThreadInput(our_tid, tid, true)) }
}

const INPUT_SIZE: i32 = size_of::<INPUT>() as i32;
const KEYDOWN: KEYBD_EVENT_FLAGS = KEYBD_EVENT_FLAGS(0);
const KEYUP: KEYBD_EVENT_FLAGS = KEYEVENTF_KEYUP;
const SCANCODEDOWN: KEYBD_EVENT_FLAGS = KEYEVENTF_SCANCODE;
const SCANCODEUP: KEYBD_EVENT_FLAGS = KEYBD_EVENT_FLAGS(KEYEVENTF_KEYUP.0 | KEYEVENTF_SCANCODE.0);

pub fn send_window_keycodes(window: HWND, keys: &[VIRTUAL_KEY], hold_time: Duration) -> Result<()> {
    let inputs: Vec<INPUT> = keys
        .iter()
        .flat_map(|key| {
            [
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: *key,
                            wScan: 0,
                            dwFlags: KEYDOWN,
                            time: 0,
                            dwExtraInfo: message_extra_info(),
                        },
                    },
                },
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: *key,
                            wScan: 0,
                            dwFlags: KEYUP,
                            time: 0,
                            dwExtraInfo: message_extra_info(),
                        },
                    },
                },
            ]
        })
        .collect();
    unsafe { bool_err(SetForegroundWindow(window))? };
    if hold_time.is_zero() {
        let inputs_sent = unsafe { u32_err(SendInput(&inputs, INPUT_SIZE))? as usize };
        if inputs_sent != inputs.len() {
            return Err(Error::new(
                ErrorKind::Other,
                "unable to send all input events to window",
            ));
        }
    } else {
        for input in inputs {
            let input_slice = &[input];
            let inputs_sent = unsafe { u32_err(SendInput(input_slice, INPUT_SIZE))? as usize };
            if inputs_sent != input_slice.len() {
                return Err(Error::new(
                    ErrorKind::Other,
                    "unable to send all input events to window",
                ));
            }
            if unsafe { input_slice[0].Anonymous.ki.dwFlags } == SCANCODEDOWN {
                std::thread::sleep(hold_time);
            }
        }
    }
    Ok(())
}

pub fn send_window_scancodes(window: HWND, scancodes: &[u16], hold_time: Duration) -> Result<()> {
    let inputs: Vec<INPUT> = scancodes
        .iter()
        .flat_map(|key| {
            [
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY::default(),
                            wScan: *key,
                            dwFlags: SCANCODEDOWN,
                            time: 0,
                            dwExtraInfo: message_extra_info(),
                        },
                    },
                },
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY::default(),
                            wScan: *key,
                            dwFlags: SCANCODEUP,
                            time: 0,
                            dwExtraInfo: message_extra_info(),
                        },
                    },
                },
            ]
        })
        .collect();
    unsafe { bool_err(SetForegroundWindow(window))? };
    if hold_time.is_zero() {
        let inputs_sent = unsafe { u32_err(SendInput(&inputs, INPUT_SIZE))? as usize };
        if inputs_sent != inputs.len() {
            return Err(Error::new(
                ErrorKind::Other,
                "unable to send all input events to window",
            ));
        }
    } else {
        for input in inputs {
            let input_slice = &[input];
            let inputs_sent = unsafe { u32_err(SendInput(input_slice, INPUT_SIZE))? as usize };
            if inputs_sent != input_slice.len() {
                return Err(Error::new(
                    ErrorKind::Other,
                    "unable to send all input events to window",
                ));
            }
            if unsafe { input_slice[0].Anonymous.ki.dwFlags } == SCANCODEDOWN {
                std::thread::sleep(hold_time);
            }
        }
    }
    Ok(())
}

struct SafeSystemInfo {
    // pub page_size: u32,
    pub minimum_application_address: usize,
    pub maximum_application_address: usize,
    // pub active_processor_mask: usize,
    // pub number_of_processors: u32,
    // pub processor_type: u32,
    // pub allocation_granularity: u32,
    // pub processor_level: u16,
    // pub processor_revision: u16,
}

impl From<SYSTEM_INFO> for SafeSystemInfo {
    fn from(value: SYSTEM_INFO) -> Self {
        Self {
            // page_size: value.dwPageSize,
            minimum_application_address: value.lpMinimumApplicationAddress as usize,
            maximum_application_address: value.lpMaximumApplicationAddress as usize,
            // active_processor_mask: value.dwActiveProcessorMask,
            // number_of_processors: value.dwNumberOfProcessors,
            // processor_type: value.dwProcessorType,
            // allocation_granularity: value.dwAllocationGranularity,
            // processor_level: value.wProcessorLevel,
            // processor_revision: value.wProcessorRevision,
        }
    }
}

fn system_info() -> SafeSystemInfo {
    let mut data = MaybeUninit::<SYSTEM_INFO>::zeroed();
    let data = unsafe {
        GetSystemInfo(data.as_mut_ptr());
        data.assume_init()
    };
    data.into()
}

fn get_proc_handle(pid: u32) -> Result<HANDLE> {
    Ok(unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)? })
}

#[derive(Debug)]
struct SafeMemoryBasicInfo {
    // pub base_address: usize,
    // pub allocation_base: usize,
    // pub allocation_protect: PAGE_PROTECTION_FLAGS,
    // pub partition_id: u16,
    pub region_size: usize,
    pub state: VIRTUAL_ALLOCATION_TYPE,
    pub protect: PAGE_PROTECTION_FLAGS,
    pub page_type: PAGE_TYPE,
}

impl From<MEMORY_BASIC_INFORMATION> for SafeMemoryBasicInfo {
    fn from(value: MEMORY_BASIC_INFORMATION) -> Self {
        Self {
            // base_address: value.BaseAddress as usize,
            // allocation_base: value.AllocationBase as usize,
            // allocation_protect: value.AllocationProtect,
            // partition_id: value.PartitionId,
            region_size: value.RegionSize,
            state: value.State,
            protect: value.Protect,
            page_type: value.Type,
        }
    }
}

fn get_addr_info(handle: HANDLE, addr: usize) -> Result<SafeMemoryBasicInfo> {
    let mut data = MaybeUninit::<MEMORY_BASIC_INFORMATION>::zeroed();
    let data = unsafe {
        usize_err(VirtualQueryEx(
            handle,
            Some(addr as *const c_void),
            data.as_mut_ptr(),
            size_of::<MEMORY_BASIC_INFORMATION>(),
        ))?;
        data.assume_init()
    };
    Ok(data.into())
}

fn read_process_memory(handle: HANDLE, addr: usize, len: usize) -> Result<Vec<u8>> {
    let mut data = Vec::<u8>::with_capacity(len);
    data.resize(len, 0);
    let mut bytes_read = MaybeUninit::new(0usize);
    let bytes_read = unsafe {
        bool_err(ReadProcessMemory(
            handle,
            addr as *const c_void,
            data.as_mut_ptr() as *mut c_void,
            len,
            Some(bytes_read.as_mut_ptr()),
        ))?;
        bytes_read.assume_init()
    };
    data.resize(bytes_read, 0);
    Ok(data)
}

pub struct MemoryDumpRegion {
    addr_min: usize,
    addr_max: usize,
    data: Vec<u8>,
}

impl MemoryDumpRegion {
    pub fn addr_min(&self) -> usize {
        self.addr_min
    }
    pub fn addr_max(&self) -> usize {
        self.addr_max
    }
    pub fn size(&self) -> usize {
        self.addr_max - self.addr_min
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn data_at(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let end = offset + len;
        if end <= self.data.len() {
            Some(&self.data[offset..end])
        } else {
            None
        }
    }
}

pub struct MemoryDump {
    addr_min: usize,
    addr_max: usize,
    regions: Vec<MemoryDumpRegion>,
}

pub struct MemoryDumpPointer {
    location: usize,
    addr: usize,
}

impl MemoryDumpPointer {
    pub fn location(&self) -> usize {
        self.location
    }
    pub fn addr(&self) -> usize {
        self.addr
    }
}

pub struct MemoryDumpIterator<'a> {
    dump: &'a MemoryDump,
    addr: usize,
}

impl<'a> Iterator for MemoryDumpIterator<'a> {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        let current_addr = self.addr;
        self.addr += 1;
        self.dump.byte(current_addr)
    }
}

impl<'a> IntoIterator for &'a MemoryDump {
    type IntoIter = MemoryDumpIterator<'a>;
    type Item = u8;
    fn into_iter(self) -> Self::IntoIter {
        MemoryDumpIterator {
            dump: self,
            addr: 0,
        }
    }
}

impl MemoryDump {
    fn byte(&self, addr: usize) -> Option<u8> {
        for region in &self.regions {
            if addr >= region.addr_min && addr < region.addr_max {
                if addr < region.addr_max {
                    let rva = addr - region.addr_min;
                    return Some(region.data[rva]);
                }
                break;
            }
        }
        None
    }

    pub fn regions(&self) -> &[MemoryDumpRegion] {
        &self.regions
    }

    pub fn data_at(&self, addr: usize, len: usize) -> Option<&[u8]> {
        for region in &self.regions {
            if addr >= region.addr_min && addr < region.addr_max {
                let rva = addr - region.addr_min;
                return region.data_at(rva, len);
            }
        }
        None
    }

    pub fn addresses_pointed_to<P>(
        &self,
        data_len: usize,
        data_predicate: P,
    ) -> Vec<MemoryDumpPointer>
    where
        P: Fn(&[u8]) -> bool,
    {
        let mut addresses = Vec::new();
        for region in &self.regions {
            let mut offset = 0;
            for possible_address in region.data.windows(8) {
                let addr = u64::from_le_bytes([
                    possible_address[0],
                    possible_address[1],
                    possible_address[2],
                    possible_address[3],
                    possible_address[4],
                    possible_address[5],
                    possible_address[6],
                    possible_address[7],
                ]) as usize;
                if addr >= self.addr_min && addr < self.addr_max {
                    if let Some(data) = self.data_at(addr, data_len) {
                        if data_predicate(data) {
                            addresses.push(MemoryDumpPointer {
                                location: region.addr_min + offset,
                                addr,
                            });
                        }
                    }
                }
                offset += 1;
            }
        }
        addresses
    }
}

pub fn dump_process_memory(pid: u32, start_addr: Option<usize>) -> Result<MemoryDump> {
    let handle = get_proc_handle(pid)?;
    let system_info = system_info();
    let addr_min = start_addr.unwrap_or(system_info.minimum_application_address);
    let addr_max = system_info.maximum_application_address;

    let mut dump = MemoryDump {
        addr_min,
        addr_max,
        regions: Vec::new(),
    };

    let mut addr = dump.addr_min;
    while addr < addr_max {
        let addr_info = get_addr_info(handle, addr)?;
        let region_size = addr_info.region_size;

        if addr_info.protect == PAGE_READWRITE
            && addr_info.page_type == MEM_PRIVATE
            && addr_info.state == MEM_COMMIT
        {
            let data = read_process_memory(handle, addr, region_size)?;
            let region = MemoryDumpRegion {
                addr_min: addr,
                addr_max: addr + region_size,
                data,
            };
            dump.regions.push(region);
        }

        addr += region_size;
    }

    Ok(dump)
}
