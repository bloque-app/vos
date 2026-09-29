//! Differential conformance of the two Refine backends, swept.
//!
//! Agents run on the Refine path: an outer standard program (the
//! AgentRuntime) that creates and invokes inner machines (the actors)
//! through the standard calls 9–14, and on Linux x86-64 Agent hosts select
//! the recompiler for both. It may execute that path only if it is
//! indistinguishable from the interpreter at every boundary a program or its
//! host can observe. Each test here runs the same work on both backends in
//! lockstep and compares, at every exit:
//!
//! - the exit itself (halt, panic, out-of-gas, page fault and its page,
//!   host call and its identifier);
//! - the remaining gas, to the unit, including out-of-gas at every block
//!   boundary (a sweep over every budget);
//! - the registers, the counter, and every mapped byte of memory;
//! - the continuation: re-invoking after a host call, a fault the host then
//!   maps, out-of-gas with more gas, and after halt or panic.
//!
//! The corpus is the Gray Paper v0.8.0 instruction and block-gas vectors
//! (`tests/vectors-v080`, `tests/vectors-v080-gas`), each run as an inner
//! machine, plus nested outer programs driven through [`RefineContext`].
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::path::{Path, PathBuf};

use serde_json::Value;
use vos_pvm::inner::{INNER_FIRST_MAPPABLE_PAGE, InnerMachines, InvokeState, PageMode};
use vos_pvm::refine::MemoryModel;
use vos_pvm::refine_host::RefineContext;
use vos_pvm::{ExitReason, PVM_PAGE_SIZE, PvmBackend};
use vos_pvm_program::{CodeBlob, build_compact_code_blob};

const BACKENDS: [PvmBackend; 2] = [PvmBackend::ForceInterpreter, PvmBackend::ForceRecompiler];

struct Vector {
    name: String,
    blob: Option<Vec<u8>>,
    pc: u32,
    gas: u64,
    regs: [u64; 13],
    /// (first page, page count, writable)
    pages: Vec<(u32, u32, bool)>,
    memory: Vec<(u32, Vec<u8>)>,
}

fn hex(value: &Value) -> Vec<u8> {
    let s = value.as_str().expect("hex string");
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex byte"))
        .collect()
}

fn register(value: &Value) -> u64 {
    let s = value.as_str().expect("register");
    u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).expect("hex register")
}

fn load_vectors(dir: &Path) -> Vec<Vector> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("vector directory")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let code = hex(&v["program"]["code"]);
            let packed = hex(&v["program"]["bitmask"]);
            let bitmask = (0..code.len())
                .map(|i| (packed.get(i / 8).copied().unwrap_or(0) >> (i % 8)) & 1)
                .collect();
            let jump_table = v["program"]["jump_table"]
                .as_array()
                .map(|t| t.iter().map(|x| x.as_u64().unwrap() as u32).collect())
                .unwrap_or_default();
            let blob = build_compact_code_blob(&CodeBlob {
                jump_table,
                code,
                bitmask,
            });
            let initial = &v["initial"];
            let mut regs = [0u64; 13];
            for (i, r) in initial["regs"].as_array().unwrap().iter().enumerate() {
                regs[i] = register(r);
            }
            let pages = initial["page_map"]
                .as_array()
                .map(|m| {
                    m.iter()
                        .map(|p| {
                            let address = p["address"].as_u64().unwrap() as u32;
                            let length = p["length"].as_u64().unwrap() as u32;
                            (
                                address / PVM_PAGE_SIZE,
                                length.div_ceil(PVM_PAGE_SIZE),
                                p["access"].as_str() == Some("rw"),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            let memory = initial["memory"]
                .as_array()
                .map(|m| {
                    m.iter()
                        .map(|c| (c["address"].as_u64().unwrap() as u32, hex(&c["contents"])))
                        .collect()
                })
                .unwrap_or_default();
            Vector {
                name: v["name"].as_str().unwrap().to_owned(),
                blob,
                pc: initial["pc"].as_u64().unwrap_or(0) as u32,
                gas: initial["gas"].as_u64().unwrap(),
                regs,
                pages,
                memory,
            }
        })
        .collect()
}

fn all_vectors() -> Vec<Vector> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut vectors = load_vectors(&root.join("vectors-v080"));
    vectors.extend(load_vectors(&root.join("vectors-v080-gas")));
    assert_eq!(vectors.len(), 173 + 16, "the whole v0.8.0 corpus");
    vectors
}

/// Everything a caller can observe of one inner-machine scenario, as text.
///
/// The scenario maps the vector's pages (those an inner machine may map),
/// writes its memory, and invokes it with `gas`. It then continues the way
/// an outer program can: after a host call it invokes again, after a fault
/// it maps the page and retries, after out-of-gas it adds `oog_step` gas,
/// and after halt or panic it invokes once more (a fresh start at counter
/// zero). Every step records the exit, gas, registers, every mapped byte and
/// the page map's refusals.
fn inner_scenario(backend: PvmBackend, v: &Vector, gas: u64, oog_step: u64) -> Vec<String> {
    let mut trace = Vec::new();
    let Some(blob) = &v.blob else {
        trace.push("unbuildable".into());
        return trace;
    };
    let mut machines = InnerMachines::with_backend(backend);
    let id = match machines.create(blob, v.pc) {
        Ok(id) => id,
        Err(e) => {
            trace.push(format!("create {e:?}"));
            return trace;
        }
    };
    let mut mapped: Vec<(u32, u32)> = Vec::new();
    for &(first, count, _) in &v.pages {
        let r = machines.pages(id, first, count, PageMode::AllocateReadWrite);
        trace.push(format!("alloc {first}+{count} {r:?}"));
        if r.is_ok() {
            mapped.push((first, count));
        }
    }
    for (address, bytes) in &v.memory {
        trace.push(format!(
            "poke {address:#x} {:?}",
            machines.poke(id, *address, bytes)
        ));
    }
    for &(first, count, writable) in &v.pages {
        if !writable {
            let r = machines.pages(id, first, count, PageMode::SetReadOnly);
            trace.push(format!("ro {first}+{count} {r:?}"));
        }
    }
    let snapshot =
        |machines: &mut InnerMachines, mapped: &[(u32, u32)], trace: &mut Vec<String>| {
            for &(first, count) in mapped {
                let bytes = machines
                    .peek(id, first * PVM_PAGE_SIZE, (count * PVM_PAGE_SIZE) as usize)
                    .expect("mapped pages are readable");
                trace.push(format!("mem {first}+{count} {:016x}", fnv(&bytes)));
            }
        };
    let mut state = InvokeState {
        gas,
        registers: v.regs,
    };
    let mut restarted = false;
    for step in 0..24u64 {
        let outcome = machines.invoke(id, state.clone()).expect("machine exists");
        trace.push(format!(
            "invoke {:?} gas {} regs {:x?}",
            outcome.exit, outcome.state.gas, outcome.state.registers
        ));
        snapshot(&mut machines, &mapped, &mut trace);
        state = outcome.state.clone();
        match outcome.exit {
            vos_pvm::inner::InnerExit::Halt | vos_pvm::inner::InnerExit::Panic => {
                if restarted {
                    break;
                }
                restarted = true;
                state.gas = state.gas.saturating_add(1_000);
            }
            vos_pvm::inner::InnerExit::Host(_) => {
                state.registers[7] = step;
            }
            vos_pvm::inner::InnerExit::Fault(address) => {
                let page = address / PVM_PAGE_SIZE;
                let r = machines.pages(id, page, 1, PageMode::AllocateReadWrite);
                trace.push(format!("map fault page {page} {r:?}"));
                if r.is_ok() {
                    mapped.push((page, 1));
                } else {
                    break;
                }
            }
            vos_pvm::inner::InnerExit::OutOfGas => {
                state.gas = state.gas.saturating_add(oog_step);
            }
        }
    }
    trace.push(format!("expunge {:?}", machines.expunge(id)));
    trace
}

fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[test]
fn v080_vectors_as_inner_machines_agree_across_backends() {
    let vectors = all_vectors();
    let mut compared = 0usize;
    for v in &vectors {
        let reference = inner_scenario(PvmBackend::ForceInterpreter, v, v.gas, 13);
        let native = inner_scenario(PvmBackend::ForceRecompiler, v, v.gas, 13);
        assert_eq!(native, reference, "{}: engines diverge", v.name);
        compared += reference.len();
    }
    eprintln!(
        "compared {compared} boundaries over {} vectors",
        vectors.len()
    );
}

/// Out-of-gas at every block boundary: every budget from zero to past the
/// whole run, and then every one-unit continuation.
#[test]
fn every_gas_budget_exits_identically_across_backends() {
    let vectors = all_vectors();
    let mut runs = 0usize;
    for v in &vectors {
        // The budget the reference run needs, bounded for the long vectors.
        let needed = {
            let mut machines = InnerMachines::new();
            match v.blob.as_ref().map(|blob| machines.create(blob, v.pc)) {
                Some(Ok(id)) => {
                    let out = machines
                        .invoke(
                            id,
                            InvokeState {
                                gas: v.gas,
                                registers: v.regs,
                            },
                        )
                        .unwrap();
                    v.gas - out.state.gas
                }
                _ => 0,
            }
        };
        for gas in 0..=needed.min(600) + 2 {
            let reference = inner_scenario(PvmBackend::ForceInterpreter, v, gas, 1);
            let native = inner_scenario(PvmBackend::ForceRecompiler, v, gas, 1);
            assert_eq!(
                native, reference,
                "{} at gas {gas}: engines diverge",
                v.name
            );
            runs += 1;
        }
    }
    eprintln!("{runs} budgets compared");
}

/// Two inner machines of one program share native code, never state.
#[test]
fn inner_machines_of_one_program_are_independent_on_the_recompiler() {
    // Store r7 at 0x10000, then host(1), then load it back into r8, trap.
    let code = [
        // load_imm r2, 0x10000
        51, 2, 0x00, 0x00, 0x01, //
        // store_ind_u64 [r2+0], r7
        123, 0x27, //
        // ecalli 1
        10, 1, //
        // load_ind_u64 r8, [r2+0]
        130, 0x28, //
        0,
    ];
    let bitmask = [1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1];
    let blob = build_compact_code_blob(&CodeBlob {
        jump_table: vec![],
        code: code.to_vec(),
        bitmask: bitmask.to_vec(),
    })
    .unwrap();
    let mut results = Vec::new();
    for backend in BACKENDS {
        let mut machines = InnerMachines::with_backend(backend);
        let a = machines.create(&blob, 0).unwrap();
        let b = machines.create(&blob, 0).unwrap();
        for id in [a, b] {
            machines
                .pages(
                    id,
                    INNER_FIRST_MAPPABLE_PAGE,
                    1,
                    PageMode::AllocateReadWrite,
                )
                .unwrap();
        }
        let mut regs = [0u64; 13];
        regs[7] = 0xAAAA;
        let first_a = machines
            .invoke(
                a,
                InvokeState {
                    gas: 10_000,
                    registers: regs,
                },
            )
            .unwrap();
        regs[7] = 0xBBBB;
        let first_b = machines
            .invoke(
                b,
                InvokeState {
                    gas: 10_000,
                    registers: regs,
                },
            )
            .unwrap();
        let second_a = machines.invoke(a, first_a.state.clone()).unwrap();
        let second_b = machines.invoke(b, first_b.state.clone()).unwrap();
        assert_eq!(second_a.state.registers[8], 0xAAAA, "{backend:?}");
        assert_eq!(second_b.state.registers[8], 0xBBBB, "{backend:?}");
        results.push(format!("{first_a:?}{first_b:?}{second_a:?}{second_b:?}"));
    }
    assert_eq!(results[0], results[1]);
}

// ---- Nested outer programs through RefineContext ----

fn standard_program(code: &[u8], starts: &[usize], rw_data: &[u8]) -> Vec<u8> {
    let bitmask: Vec<u8> = (0..code.len())
        .map(|i| u8::from(starts.contains(&i)))
        .collect();
    let code_blob = build_compact_code_blob(&CodeBlob {
        jump_table: vec![],
        code: code.to_vec(),
        bitmask,
    })
    .unwrap();
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0; 3]);
    blob.extend_from_slice(&(rw_data.len() as u32).to_le_bytes()[..3]);
    blob.extend_from_slice(&1u16.to_le_bytes());
    blob.extend_from_slice(&4096u32.to_le_bytes()[..3]);
    blob.extend_from_slice(rw_data);
    blob.extend_from_slice(&(code_blob.len() as u32).to_le_bytes());
    blob.extend_from_slice(&code_blob);
    blob
}

const RW_BASE: u32 = 2 * vos_pvm::PVM_ZONE_SIZE;

/// The outer programs: each creates an inner machine from its arguments and
/// drives it through the standard calls, or faults, or calls the embedder.
fn outer_programs() -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
    let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
    let mut frame = [0u8; 112];
    frame[..8].copy_from_slice(&2_000u64.to_le_bytes());
    // An inner program: host(42), then trap.
    let host_then_trap = vec![0, 1, 3, 10, 42, 0, 0b0000_0101];
    // An inner program that loads from 0x10000: faults until mapped.
    let inner_load = build_compact_code_blob(&CodeBlob {
        jump_table: vec![],
        code: vec![51, 2, 0x00, 0x00, 0x01, 130, 0x23, 0],
        bitmask: vec![1, 0, 0, 0, 0, 1, 0, 1],
    })
    .unwrap();
    vec![
        (
            // machine(args); r8 <- RW_BASE; invoke(0, frame); halt.
            "machine_invoke_host",
            standard_program(
                &[10, 9, 51, 8, b0, b1, b2, 10, 13, 50, 0],
                &[0, 2, 7, 9],
                &frame,
            ),
            host_then_trap.clone(),
        ),
        (
            // machine; r8 <- RW_BASE; invoke twice (host, then trap); expunge; halt.
            "invoke_twice_then_expunge",
            standard_program(
                &[
                    10, 9, 51, 8, b0, b1, b2, 10, 13, 51, 7, 0, 51, 8, b0, b1, b2, 10, 13, 51, 7,
                    0, 10, 14, 50, 0,
                ],
                &[0, 2, 7, 9, 12, 17, 19, 22, 24],
                &frame,
            ),
            host_then_trap,
        ),
        (
            // machine; invoke → fault at 0x10000; pages(0, 16, 1, rw); invoke again; halt.
            "fault_then_map_then_retry",
            standard_program(
                &[
                    10, 9, // machine
                    51, 8, b0, b1, b2, // r8 <- frame
                    10, 13, // invoke
                    51, 7, 0, // r7 <- 0 (id)
                    51, 8, 16, // r8 <- first page 16
                    51, 9, 1, // r9 <- 1 page
                    51, 10, 2, // r10 <- allocate rw
                    10, 12, // pages
                    51, 7, 0, // r7 <- 0
                    51, 8, b0, b1, b2, // r8 <- frame
                    10, 13, // invoke
                    50, 0, // halt
                ],
                &[0, 2, 7, 9, 12, 15, 18, 21, 23, 26, 31, 33],
                &frame,
            ),
            inner_load,
        ),
        (
            // r2 <- 9; external(77); external(77); halt.
            "embedder_calls",
            standard_program(&[51, 2, 9, 10, 77, 10, 77, 50, 0], &[0, 3, 5, 7], &[]),
            vec![],
        ),
        (
            // A load from the unmapped gap above the read-write zone.
            "outer_page_fault",
            standard_program(&[51, 3, 0x00, 0x00, 0x04, 130, 0x34, 0], &[0, 5, 7], &[]),
            vec![],
        ),
        (
            // A write into the read-only argument zone.
            "outer_readonly_write",
            standard_program(&[120, 0x72, 0], &[0, 2], &[]),
            vec![1, 2, 3, 4],
        ),
    ]
}

fn outer_run(backend: PvmBackend, program: &[u8], args: &[u8], gas: u64) -> String {
    let context =
        match RefineContext::load_with_backend(program, args, gas, MemoryModel::Auto, backend) {
            Ok(context) => context,
            Err(e) => return format!("load {e:?}"),
        };
    let invocation = context.try_run_with_host(|id, machine| {
        if id != 77 {
            return Err(ExitReason::HostCall(id));
        }
        if !machine.charge(50) {
            return Err(ExitReason::OutOfGas);
        }
        machine.registers_mut()[2] += 1;
        Ok(())
    });
    let invocation = match invocation {
        Ok(invocation) => invocation,
        Err(e) => return format!("backend {e:?}"),
    };
    let mut frame = [0u8; 112];
    let frame_read = invocation.memory().read_bytes_checked(RW_BASE, &mut frame);
    format!(
        "{:?} pc {} gas {} regs {:x?} out {:?} frame {} {:016x}",
        invocation.exit,
        invocation.pc,
        invocation.gas_used,
        invocation.registers,
        invocation.output_bounded(4096),
        frame_read,
        fnv(&frame)
    )
}

#[test]
fn nested_refine_programs_agree_across_backends_at_every_budget() {
    for (name, program, args) in outer_programs() {
        let full = outer_run(PvmBackend::ForceInterpreter, &program, &args, 10_000_000);
        assert_eq!(
            outer_run(PvmBackend::ForceRecompiler, &program, &args, 10_000_000),
            full,
            "{name}"
        );
        // Sweep every budget from below the whole run's execution (the
        // standard init charge is 1 500 gas per mapped page) to past it.
        let used = {
            let context = RefineContext::load(&program, &args, 10_000_000).unwrap();
            let invocation = context.run_with_host(|_, machine| {
                machine.charge(50);
                machine.registers_mut()[2] += 1;
                Ok(())
            });
            invocation.gas_used
        };
        let low = used.saturating_sub(8_000);
        for gas in (low..=used + 3).step_by(1) {
            let reference = outer_run(PvmBackend::ForceInterpreter, &program, &args, gas);
            let native = outer_run(PvmBackend::ForceRecompiler, &program, &args, gas);
            assert_eq!(native, reference, "{name} at gas {gas}");
        }
    }
}
