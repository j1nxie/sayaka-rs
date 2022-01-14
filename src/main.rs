#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate bitflags;

pub mod cpu;
pub mod opcodes;

use crate::cpu::CPU;

fn main() {
    let game_code = vec![];

    let mut cpu = CPU::new();
    cpu.load(game_code);
    cpu.reset();

    cpu.run_with_callback(move |cpu| {
        // TODO:
        // read user input -> write to mem[0xFF]
        // update mem[0xFE] with new random number
        // read memory mapped screen state
        // render screen state
    });
}
