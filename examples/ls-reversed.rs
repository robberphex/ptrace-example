use libc::c_void;
use nix::sys::ptrace;
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::os::unix::process::CommandExt;
use std::process::{exit, Command, Stdio};

// from https://www.linuxjournal.com/article/6100
fn main() {
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            run_child();
        }

        Ok(ForkResult::Parent { child }) => {
            run_parent(child);
        }

        Err(err) => {
            panic!("[main] fork() failed: {}", err);
        }
    };
}

// Code that runs only for parent
fn run_parent(pid: Pid) {
    let mut insyscall = 0;
    loop {
        match wait() {
            Ok(WaitStatus::Stopped(_pid_t, _sig_num)) => {
                let regs = ptrace::getregs(pid).unwrap();
                let orig_rax = regs.orig_rax as libc::c_long;
                log::debug!("The child made a system call {}", orig_rax);
                if orig_rax == libc::SYS_write {
                    if insyscall == 0 {
                        /* Syscall entry */
                        insyscall = 1;
                        let fd = regs.rdi as libc::c_long;
                        let buf_addr = regs.rsi as libc::c_long;
                        let nbytes = regs.rdx as libc::c_long;
                        log::debug!("Write called with {}, {}, {}", fd, buf_addr, nbytes);
                        let mut buf: Vec<u8> = Vec::new();
                        get_data(pid, buf_addr, &mut buf, nbytes);
                        reverse(&mut buf);
                        put_data(pid, buf_addr, &mut buf, nbytes);
                    } else {
                        /* Syscall exit */
                        let rax = regs.rax as libc::c_long;
                        log::debug!("Write returned with {}", rax);
                        insyscall = 0;
                    }
                }
            }
            Ok(WaitStatus::Exited(pid, exit_status)) => {
                log::debug!(
                    "Process with pid: {} exited with status {}",
                    pid,
                    exit_status
                );
                break;
            }
            Ok(status) => {
                log::debug!("Received status: {:?}", status);
            }
            Err(err) => {
                log::debug!("Some kind of error - {:?}", err);
            }
        }
        ptrace::syscall(pid, None).expect("ptrace::syscall");
    }
}

// Code that runs only for child
fn run_child() {
    // Allows process to be traced
    ptrace::traceme().unwrap();

    Command::new("/bin/ls")
        .arg("-a")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .exec();
    // Command::new("/usr/bin/echo")
    //     .arg("12345678abcdef")
    //     .stdout(Stdio::inherit())
    //     .stderr(Stdio::inherit())
    //     .exec();

    exit(0);
}

fn get_data(pid: Pid, addr: i64, buf: &mut Vec<u8>, len: i64) {
    let word_size: i64 = 8;
    let mut i: i64 = 0;
    let mut j: i64 = len / word_size;
    while i < j {
        let mut value = ptrace::read(pid, (addr + i * 8) as *mut _).unwrap();
        log::debug!("[get_data]addr={:x},value={:x}", (addr + i * 8), value);
        i += 1;

        // 0
        buf.push((value - (value >> 8 << 8)) as u8);
        value = value >> 8;
        // 1
        buf.push((value - (value >> 8 << 8)) as u8);
        value = value >> 8;
        // 2
        buf.push((value - (value >> 8 << 8)) as u8);
        value = value >> 8;
        // 3
        buf.push((value - (value >> 8 << 8)) as u8);
        value = value >> 8;
        // 4
        buf.push((value - (value >> 8 << 8)) as u8);
        value = value >> 8;
        // 5
        buf.push((value - (value >> 8 << 8)) as u8);
        value = value >> 8;
        // 6
        buf.push((value - (value >> 8 << 8)) as u8);
        value = value >> 8;
        // 7
        buf.push((value - (value >> 8 << 8)) as u8);
    }
    j = len % word_size;
    log::debug!("[get_data]j={}", j);
    if j != 0 {
        let mut value = ptrace::read(pid, (addr + i * 8) as *mut _).unwrap();
        log::debug!("[get_data]addr={:x},value={:x}", (addr + i * 8), value);
        while j > 0 {
            buf.push((value - (value >> 8 << 8)) as u8);
            value = value >> 8;
            j -= 1;
        }
    }
    let buf_str = String::from_utf8(buf.to_vec()).unwrap();
    log::debug!("[get_data]buf={:?}", buf_str);
}

fn reverse(buf: &mut Vec<u8>) {
    let buf_str = String::from_utf8(buf.to_vec()).unwrap();
    log::debug!("[reverse]before.buf={:?}", buf_str);
    if buf.len() >= 2 {
        let mut i = 0;
        let mut j = buf.len() - 2;
        while i <= j && j >= 1 {
            let temp = *buf.get(i).unwrap();
            *buf.get_mut(i).unwrap() = *buf.get(j).unwrap();
            *buf.get_mut(j).unwrap() = temp;
            i += 1;
            j -= 1;
        }
    }
    let buf_str = String::from_utf8(buf.to_vec()).unwrap();
    log::debug!("[reverse]after.buf={:?}", buf_str);
}

fn put_data(pid: Pid, addr: i64, buf: &mut Vec<u8>, len: i64) {
    let word_size: i64 = 8;
    let mut i: i64 = 0;
    let mut j: i64 = len / word_size;
    while i < j {
        let mut value: i64 = 0;

        // 0
        let tmp = *buf.get((i * 8) as usize).unwrap() as i64;
        value += tmp << 0;

        // 1
        let tmp = *buf.get((i * 8 + 1) as usize).unwrap() as i64;
        value += tmp << 8;

        // 2
        let tmp = *buf.get((i * 8 + 2) as usize).unwrap() as i64;
        value += tmp << 16;

        // 3
        let tmp = *buf.get((i * 8 + 3) as usize).unwrap() as i64;
        value += tmp << 24;

        // 4
        let tmp = *buf.get((i * 8 + 4) as usize).unwrap() as i64;
        value += tmp << 32;

        // 5
        let tmp = *buf.get((i * 8 + 5) as usize).unwrap() as i64;
        value += tmp << 40;

        // 6
        let tmp = *buf.get((i * 8 + 6) as usize).unwrap() as i64;
        value += tmp << 48;

        // 7
        let tmp = *buf.get((i * 8 + 7) as usize).unwrap() as i64;
        value += tmp << 56;

        unsafe {
            ptrace::write(pid, (addr + i * 8) as *mut _, value as *mut c_void).unwrap();
        }
        value = ptrace::read(pid, (addr + i * 8) as *mut _).unwrap();
        log::debug!("[put_data]addr={:x},value={:x}", (addr + i * 8), value);
        log::debug!("[put_data]value f: {:x}", value);
        i += 1;
    }
    j = len % word_size;
    log::debug!("[put_data]j={}", j);
    if j != 0 {
        let mut value = ptrace::read(pid, (addr + i * 8) as *mut _).unwrap();
        log::debug!("[put_data] get addr={:x},value={:x}", (addr + i * 8), value);

        // 0
        if j > 0 {
            let tmp = *buf.get((i * 8) as usize).unwrap() as i64;
            value &= !(0xff << 0);
            value += tmp << 0;
        }

        // 1
        if j > 1 {
            let tmp = *buf.get((i * 8 + 1) as usize).unwrap() as i64;
            value &= !(0xff << 8);
            value += tmp << 8;
        }

        // 2
        if j > 2 {
            let tmp = *buf.get((i * 8 + 2) as usize).unwrap() as i64;
            value &= !(0xff << 16);
            value += tmp << 16;
        }

        // 3
        if j > 3 {
            let tmp = *buf.get((i * 8 + 3) as usize).unwrap() as i64;
            value &= !(0xff << 24);
            value += tmp << 24;
        }

        // 4
        if j > 4 {
            let tmp = *buf.get((i * 8 + 4) as usize).unwrap() as i64;
            value &= !(0xff << 32);
            value += tmp << 32;
        }

        // 5
        if j > 5 {
            let tmp = *buf.get((i * 8 + 5) as usize).unwrap() as i64;
            value &= !(0xff << 40);
            value += tmp << 40;
        }

        // 6
        if j > 6 {
            let tmp = *buf.get((i * 8 + 6) as usize).unwrap() as i64;
            value &= !(0xff << 48);
            value += tmp << 48;
        }
        log::debug!("[put_data]last addr={:x},value={:x}", (addr + i * 8), value);
        unsafe {
            ptrace::write(pid, (addr + i * 8) as *mut _, value as *mut c_void).unwrap();
        }
    }
}
