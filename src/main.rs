use derive_try_from_primitive::TryFromPrimitive;
use std::io;
use std::path::Path;
use std::time::Instant;

const VERBOSE_PRINTS: bool = false;

/// permission bytes
const PERM_READ: u8 = 1 << 0;
const PERM_WRITE: u8 = 1 << 1;
const PERM_EXEC: u8 = 1 << 2;
const PERM_RAW: u8 = 1 << 3;

unsafe trait Primitive: Default + Clone + Copy {}

unsafe impl Primitive for u8 {}
unsafe impl Primitive for u16 {}
unsafe impl Primitive for u32 {}
unsafe impl Primitive for u64 {}
unsafe impl Primitive for u128 {}
unsafe impl Primitive for usize {}
unsafe impl Primitive for i8 {}
unsafe impl Primitive for i16 {}
unsafe impl Primitive for i32 {}
unsafe impl Primitive for i64 {}
unsafe impl Primitive for i128 {}
unsafe impl Primitive for isize {}

/// dirty block size sweet spot is between 128-4096
const DIRTY_BLOCK_SIZE: usize = 4096;

// permission bytes corresponding to the memory byte
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Perm(u8);

// a guest virtual address
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct VirtAddr(usize);

struct Mmu {
    memory: Vec<u8>,

    /// permission bits for the corresponding bytes
    permission: Vec<Perm>,

    /// current base addresss of the next allocation
    curr_alc: VirtAddr,

    /// starting index of all the dirty blocks
    dirty_block: Vec<VirtAddr>,

    ///
    dirty_bitmap: Vec<u64>,
}

impl Mmu {
    pub fn new(size: usize) -> Self {
        Self {
            memory: vec![0; size],
            permission: vec![Perm(0); size],
            curr_alc: VirtAddr(0x1000),
            dirty_block: Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0u64; (size / DIRTY_BLOCK_SIZE + 1) / 64],
        }
    }

    pub fn allocate(&mut self, size: usize) -> Option<VirtAddr> {
        // 16 byte alignment
        let aligned_size = (size + 0xf) & !0xf;

        if self.memory.len() >= self.curr_alc.0.checked_add(aligned_size)? {
            let curr_base = self.curr_alc;

            // set permissions to write and raw
            let perm = PERM_WRITE | PERM_RAW;
            self.set_permissions(curr_base, aligned_size, Perm(perm))
                .unwrap();

            // update current base address
            self.curr_alc = VirtAddr(self.curr_alc.0.checked_add(aligned_size)?);

            Some(curr_base)
        } else {
            None
        }
    }

    /// Return an immutable slice to memory at `addr` for `size` bytes that
    /// has been validated to match all `exp_perms`
    pub fn peek_perms(
        &self,
        addr: VirtAddr,
        size: usize,
        exp_perms: Perm,
    ) -> Result<&[u8], VmExit> {
        let perms = self
            .permission
            .get(
                addr.0
                    ..addr
                        .0
                        .checked_add(size)
                        .ok_or(VmExit::AddressIntegerOverflow)?,
            )
            .ok_or(VmExit::AddressMiss(addr, size))?;

        // Check permissions
        for (idx, &perm) in perms.iter().enumerate() {
            if (perm.0 & exp_perms.0) != exp_perms.0 {
                return Err(VmExit::ReadFault(VirtAddr(addr.0 + idx)));
            }
        }

        // Return a slice to the memory
        Ok(&self.memory[addr.0..addr.0 + size])
    }

    pub fn read_into_perms(
        &self,
        addr: VirtAddr,
        buf: &mut [u8],
        exp_perms: Perm,
    ) -> Result<(), VmExit> {
        let perms = self
            .permission
            .get(
                addr.0
                    ..addr
                        .0
                        .checked_add(buf.len())
                        .ok_or(VmExit::AddressIntegerOverflow)?,
            )
            .ok_or(VmExit::AddressMiss(addr, buf.len()))?;

        // Check permissions
        for (idx, &perm) in perms.iter().enumerate() {
            if (perm.0 & exp_perms.0) != exp_perms.0 {
                return Err(VmExit::ReadFault(VirtAddr(addr.0 + idx)));
            }
        }

        buf.copy_from_slice(&self.memory[addr.0..addr.0 + buf.len()]);

        Ok(())
    }

    /// read into the buffer from a given virt address
    pub fn read_into(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<(), VmExit> {
        self.read_into_perms(addr, buf, Perm(PERM_READ))
    }

    /// write to the virt address from the given buffer
    pub fn write_from(&mut self, addr: VirtAddr, buf: &[u8]) -> Result<(), VmExit> {
        let perms = self
            .permission
            .get_mut(
                addr.0
                    ..addr
                        .0
                        .checked_add(buf.len())
                        .ok_or(VmExit::AddressIntegerOverflow)?,
            )
            .ok_or(VmExit::AddressMiss(addr, buf.len()))?;

        // Check permissions
        let mut has_raw = false;
        for (idx, &perm) in perms.iter().enumerate() {
            // Accumulate if any permission has the raw bit set, this will
            // allow us to bypass permission updates if no RAW is in use
            has_raw |= (perm.0 & PERM_RAW) != 0;

            if (perm.0 & PERM_WRITE) == 0 {
                // Permission denied, return error
                return Err(VmExit::WriteFault(VirtAddr(addr.0 + idx)));
            }
        }

        // write from the buffer
        self.memory[addr.0..(addr.0 + buf.len())].copy_from_slice(buf);

        // set dirty blocks
        // block where the dirtiness starts from
        let block_start = addr.0 / DIRTY_BLOCK_SIZE;
        // block where the dirtiness ends
        let block_end = (addr.0 + buf.len()) / DIRTY_BLOCK_SIZE;

        for block_idx in block_start..=block_end {
            let idx = block_idx / 64;
            let bit = block_idx % 64;

            // set dirty if not already
            if self.dirty_bitmap[idx] & (1 << bit) == 0 {
                self.dirty_bitmap[idx] |= 1 << bit;
            }

            // update the dirty blocks list
            self.dirty_block
                .push(VirtAddr(block_idx * DIRTY_BLOCK_SIZE));
        }

        // Update RaW bits
        if has_raw {
            perms.iter_mut().for_each(|x| {
                if (x.0 & PERM_RAW) != 0 {
                    // Mark memory as readable
                    *x = Perm(x.0 | PERM_READ);
                }
            });
        }

        Ok(())
    }

    /// Read a type T at vaddr expecting 'perms'
    pub fn read_perms<T: Primitive>(
        &mut self,
        addr: VirtAddr,
        exp_perms: Perm,
    ) -> Result<T, VmExit> {
        let mut tmp = [0u8; 16];
        self.read_into_perms(addr, &mut tmp[..core::mem::size_of::<T>()], exp_perms)?;
        Ok(unsafe { core::ptr::read_unaligned(tmp.as_ptr() as *const T) })
    }

    /// Read type T at vaddr
    pub fn read<T: Primitive>(&mut self, addr: VirtAddr) -> Result<T, VmExit> {
        self.read_perms(addr, Perm(PERM_READ))
    }

    /// write a val to addr
    pub fn write<T: Primitive>(&mut self, addr: VirtAddr, val: T) -> Result<(), VmExit> {
        let tmp = unsafe {
            core::slice::from_raw_parts(&val as *const T as *const u8, core::mem::size_of::<T>())
        };

        self.write_from(addr, tmp)
    }

    pub fn set_permissions(&mut self, addr: VirtAddr, size: usize, perm: Perm) -> Option<()> {
        self.permission[addr.0..(addr.0.checked_add(size))?]
            .iter_mut()
            .for_each(|x| {
                *x = perm;
            });
        Some(())
    }

    /// fork the mmu at its current state for a fresh state
    pub fn fork(&self) -> Self {
        let size = self.memory.len();
        // copy memory, permission and the current allocation base and leave the rest
        Mmu {
            memory: self.memory.clone(),
            permission: self.permission.clone(),
            curr_alc: self.curr_alc,
            dirty_block: Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0u64; (size / DIRTY_BLOCK_SIZE + 1) / 64],
        }
    }

    /// reset the dirty blocks to their original state. The original state is also needed
    pub fn reset(&mut self, other: &Mmu) {
        for addr in self.dirty_block.drain(0..) {
            // reset the dirtied block memory
            self.memory[addr.0..(addr.0 + DIRTY_BLOCK_SIZE)]
                .copy_from_slice(&other.memory[addr.0..(addr.0 + DIRTY_BLOCK_SIZE)]);

            // reset the dirtied block permission
            self.permission[addr.0..(addr.0 + DIRTY_BLOCK_SIZE)]
                .copy_from_slice(&other.permission[addr.0..(addr.0 + DIRTY_BLOCK_SIZE)]);

            // empty the dirty block virt address list and reset the bitmap wherever required
            self.dirty_bitmap[addr.0 / DIRTY_BLOCK_SIZE] = 0;
        }
    }

    /// Load a file into the emulators address space using the sections as
    /// described
    pub fn load<P: AsRef<Path>>(&mut self, filename: P, sections: &[Section]) -> Option<()> {
        // Read the input file
        let contents = std::fs::read(filename).ok()?;

        // Go through each section and load it
        for section in sections {
            // Set memory to writable
            self.set_permissions(section.virt_addr, section.mem_size, Perm(PERM_WRITE))?;

            // Write in the original file contents
            self.write_from(
                section.virt_addr,
                contents.get(section.file_off..section.file_off.checked_add(section.file_size)?)?,
            )
            .ok()?;

            // Write in any padding with zeros
            if section.mem_size > section.file_size {
                let padding = vec![0u8; section.mem_size - section.file_size];
                self.write_from(
                    VirtAddr(section.virt_addr.0.checked_add(section.file_size)?),
                    &padding,
                )
                .ok()?;
            }

            // Demote permissions to originals
            self.set_permissions(section.virt_addr, section.mem_size, section.permissions)?;

            // Update the allocator beyond any sections we load
            self.curr_alc = VirtAddr(std::cmp::max(
                self.curr_alc.0,
                (section.virt_addr.0 + section.mem_size + 0xf) & !0xf,
            ));
        }

        Some(())
    }
}

struct Section {
    file_off: usize,
    virt_addr: VirtAddr,
    file_size: usize,
    mem_size: usize,
    permissions: Perm,
}

struct Emulator {
    memory: Mmu,
    registers: [u64; 33],
}

impl Emulator {
    pub fn new(size: usize) -> Self {
        Emulator {
            memory: Mmu::new(size),
            registers: [0u64; 33],
        }
    }

    pub fn fork(&self) -> Self {
        Emulator {
            memory: self.memory.fork(),
            registers: self.registers.clone(),
        }
    }

    /// reset the state of self to other assuming self was forked from other
    pub fn reset(&mut self, other: &Self) {
        // reset memory
        self.memory.reset(&other.memory);

        // reset registers
        self.registers = other.registers
    }

    /// get a register value
    fn get_reg(&self, register: Register) -> u64 {
        if register != Register::Zero {
            self.registers[register as usize]
        } else {
            0
        }
    }

    /// set a register value
    fn set_reg(&mut self, register: Register, value: u64) {
        self.registers[register as usize] = value;
    }

    pub fn run(&mut self) -> Result<(), VmExit> {
        'next_inst: loop {
            // Get the current program counter
            let pc = self.get_reg(Register::Pc);
            let inst: u32 = self
                .memory
                .read_perms(VirtAddr(pc as usize), Perm(PERM_EXEC))?;

            // Extract the opcode from the instruction
            let opcode = inst & 0b1111111;

            // print!("Executing {:#x} {:b}\n", pc, opcode);

            match opcode {
                0b0110111 => {
                    // LUI
                    let inst = Utype::from(inst);
                    self.set_reg(inst.rd, inst.imm as i64 as u64);
                }
                0b0010111 => {
                    // AUIPC
                    let inst = Utype::from(inst);
                    self.set_reg(inst.rd, (inst.imm as i64 as u64).wrapping_add(pc));
                }
                0b1101111 => {
                    // JAL
                    let inst = Jtype::from(inst);
                    self.set_reg(inst.rd, pc.wrapping_add(4));
                    self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                    continue 'next_inst;
                }
                0b1100111 => {
                    // We know it's an Itype
                    let inst = Itype::from(inst);

                    match inst.funct3 {
                        0b000 => {
                            // JALR
                            let target =
                                self.get_reg(inst.rs1).wrapping_add(inst.imm as i64 as u64);
                            self.set_reg(inst.rd, pc.wrapping_add(4));
                            self.set_reg(Register::Pc, target);
                            continue 'next_inst;
                        }
                        _ => unimplemented!("Unexpected 0b1100111"),
                    }
                }
                0b1100011 => {
                    // We know it's an Btype
                    let inst = Btype::from(inst);

                    let rs1 = self.get_reg(inst.rs1);
                    let rs2 = self.get_reg(inst.rs2);

                    match inst.funct3 {
                        0b000 => {
                            // BEQ
                            if rs1 == rs2 {
                                self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b001 => {
                            // BNE
                            if rs1 != rs2 {
                                self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b100 => {
                            // BLT
                            if (rs1 as i64) < (rs2 as i64) {
                                self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b101 => {
                            // BGE
                            if (rs1 as i64) >= (rs2 as i64) {
                                self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b110 => {
                            // BLTU
                            if (rs1 as u64) < (rs2 as u64) {
                                self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b111 => {
                            // BGEU
                            if (rs1 as u64) >= (rs2 as u64) {
                                self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        _ => unimplemented!("Unexpected 0b1100011"),
                    }
                }
                0b0000011 => {
                    // We know it's an Itype
                    let inst = Itype::from(inst);

                    // Compute the address
                    let addr = VirtAddr(
                        self.get_reg(inst.rs1).wrapping_add(inst.imm as i64 as u64) as usize,
                    );

                    match inst.funct3 {
                        0b000 => {
                            // LB
                            let mut tmp = [0u8; 1];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, i8::from_le_bytes(tmp) as i64 as u64);
                        }
                        0b001 => {
                            // LH
                            let mut tmp = [0u8; 2];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, i16::from_le_bytes(tmp) as i64 as u64);
                        }
                        0b010 => {
                            // LW
                            let mut tmp = [0u8; 4];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, i32::from_le_bytes(tmp) as i64 as u64);
                        }
                        0b011 => {
                            // LD
                            let mut tmp = [0u8; 8];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, i64::from_le_bytes(tmp) as i64 as u64);
                        }
                        0b100 => {
                            // LBU
                            let mut tmp = [0u8; 1];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, u8::from_le_bytes(tmp) as u64);
                        }
                        0b101 => {
                            // LHU
                            let mut tmp = [0u8; 2];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, u16::from_le_bytes(tmp) as u64);
                        }
                        0b110 => {
                            // LWU
                            let mut tmp = [0u8; 4];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, u32::from_le_bytes(tmp) as u64);
                        }
                        _ => unimplemented!("Unexpected 0b0000011"),
                    }
                }
                0b0100011 => {
                    // We know it's an Stype
                    let inst = Stype::from(inst);

                    // Compute the address
                    let addr = VirtAddr(
                        self.get_reg(inst.rs1).wrapping_add(inst.imm as i64 as u64) as usize,
                    );

                    match inst.funct3 {
                        0b000 => {
                            // SB
                            let val = self.get_reg(inst.rs2) as u8;
                            self.memory.write(addr, val)?;
                        }
                        0b001 => {
                            // SH
                            let val = self.get_reg(inst.rs2) as u16;
                            self.memory.write(addr, val)?;
                        }
                        0b010 => {
                            // SW
                            let val = self.get_reg(inst.rs2) as u32;
                            self.memory.write(addr, val)?;
                        }
                        0b011 => {
                            // SD
                            let val = self.get_reg(inst.rs2) as u64;
                            self.memory.write(addr, val)?;
                        }
                        _ => unimplemented!("Unexpected 0b0100011"),
                    }
                }
                0b0010011 => {
                    // We know it's an Itype
                    let inst = Itype::from(inst);

                    let rs1 = self.get_reg(inst.rs1);
                    let imm = inst.imm as i64 as u64;

                    match inst.funct3 {
                        0b000 => {
                            // ADDI
                            self.set_reg(inst.rd, rs1.wrapping_add(imm));
                        }
                        0b010 => {
                            // SLTI
                            if (rs1 as i64) < (imm as i64) {
                                self.set_reg(inst.rd, 1);
                            } else {
                                self.set_reg(inst.rd, 0);
                            }
                        }
                        0b011 => {
                            // SLTIU
                            if (rs1 as u64) < (imm as u64) {
                                self.set_reg(inst.rd, 1);
                            } else {
                                self.set_reg(inst.rd, 0);
                            }
                        }
                        0b100 => {
                            // XORI
                            self.set_reg(inst.rd, rs1 ^ imm);
                        }
                        0b110 => {
                            // ORI
                            self.set_reg(inst.rd, rs1 | imm);
                        }
                        0b111 => {
                            // ANDI
                            self.set_reg(inst.rd, rs1 & imm);
                        }
                        0b001 => {
                            let mode = (inst.imm >> 6) & 0b111111;

                            match mode {
                                0b000000 => {
                                    // SLLI
                                    let shamt = inst.imm & 0b111111;
                                    self.set_reg(inst.rd, rs1 << shamt);
                                }
                                _ => unreachable!(),
                            }
                        }
                        0b101 => {
                            let mode = (inst.imm >> 6) & 0b111111;

                            match mode {
                                0b000000 => {
                                    // SRLI
                                    let shamt = inst.imm & 0b111111;
                                    self.set_reg(inst.rd, rs1 >> shamt);
                                }
                                0b010000 => {
                                    // SRAI
                                    let shamt = inst.imm & 0b111111;
                                    self.set_reg(inst.rd, ((rs1 as i64) >> shamt) as u64);
                                }
                                _ => unreachable!(),
                            }
                        }
                        _ => unreachable!(),
                    }
                }
                0b0110011 => {
                    // We know it's an Rtype
                    let inst = Rtype::from(inst);

                    let rs1 = self.get_reg(inst.rs1);
                    let rs2 = self.get_reg(inst.rs2);

                    match (inst.funct7, inst.funct3) {
                        (0b0000000, 0b000) => {
                            // ADD
                            self.set_reg(inst.rd, rs1.wrapping_add(rs2));
                        }
                        (0b0100000, 0b000) => {
                            // SUB
                            self.set_reg(inst.rd, rs1.wrapping_sub(rs2));
                        }
                        (0b0000000, 0b001) => {
                            // SLL
                            let shamt = rs2 & 0b111111;
                            self.set_reg(inst.rd, rs1 << shamt);
                        }
                        (0b0000000, 0b010) => {
                            // SLT
                            if (rs1 as i64) < (rs2 as i64) {
                                self.set_reg(inst.rd, 1);
                            } else {
                                self.set_reg(inst.rd, 0);
                            }
                        }
                        (0b0000000, 0b011) => {
                            // SLTU
                            if (rs1 as u64) < (rs2 as u64) {
                                self.set_reg(inst.rd, 1);
                            } else {
                                self.set_reg(inst.rd, 0);
                            }
                        }
                        (0b0000000, 0b100) => {
                            // XOR
                            self.set_reg(inst.rd, rs1 ^ rs2);
                        }
                        (0b0000000, 0b101) => {
                            // SRL
                            let shamt = rs2 & 0b111111;
                            self.set_reg(inst.rd, rs1 >> shamt);
                        }
                        (0b0100000, 0b101) => {
                            // SRA
                            let shamt = rs2 & 0b111111;
                            self.set_reg(inst.rd, ((rs1 as i64) >> shamt) as u64);
                        }
                        (0b0000000, 0b110) => {
                            // OR
                            self.set_reg(inst.rd, rs1 | rs2);
                        }
                        (0b0000000, 0b111) => {
                            // AND
                            self.set_reg(inst.rd, rs1 & rs2);
                        }
                        _ => unreachable!(),
                    }
                }
                0b0111011 => {
                    // We know it's an Rtype
                    let inst = Rtype::from(inst);

                    let rs1 = self.get_reg(inst.rs1) as u32;
                    let rs2 = self.get_reg(inst.rs2) as u32;

                    match (inst.funct7, inst.funct3) {
                        (0b0000000, 0b000) => {
                            // ADDW
                            self.set_reg(inst.rd, rs1.wrapping_add(rs2) as i32 as i64 as u64);
                        }
                        (0b0100000, 0b000) => {
                            // SUBW
                            self.set_reg(inst.rd, rs1.wrapping_sub(rs2) as i32 as i64 as u64);
                        }
                        (0b0000000, 0b001) => {
                            // SLLW
                            let shamt = rs2 & 0b11111;
                            self.set_reg(inst.rd, (rs1 << shamt) as i32 as i64 as u64);
                        }
                        (0b0000000, 0b101) => {
                            // SRLW
                            let shamt = rs2 & 0b11111;
                            self.set_reg(inst.rd, (rs1 >> shamt) as i32 as i64 as u64);
                        }
                        (0b0100000, 0b101) => {
                            // SRAW
                            let shamt = rs2 & 0b11111;
                            self.set_reg(inst.rd, ((rs1 as i32) >> shamt) as i64 as u64);
                        }
                        _ => unreachable!(),
                    }
                }
                0b0001111 => {
                    let inst = Itype::from(inst);

                    match inst.funct3 {
                        0b000 => {
                            // FENCE
                        }
                        _ => unreachable!(),
                    }
                }
                0b1110011 => {
                    if inst == 0b00000000000000000000000001110011 {
                        // ECALL
                        return Err(VmExit::Syscall);
                    } else if inst == 0b00000000000100000000000001110011 {
                        // EBREAK
                    } else {
                        unreachable!();
                    }
                }
                0b0011011 => {
                    // We know it's an Itype
                    let inst = Itype::from(inst);

                    let rs1 = self.get_reg(inst.rs1) as u32;
                    let imm = inst.imm as u32;

                    match inst.funct3 {
                        0b000 => {
                            // ADDIW
                            self.set_reg(inst.rd, rs1.wrapping_add(imm) as i32 as i64 as u64);
                        }
                        0b001 => {
                            let mode = (inst.imm >> 5) & 0b1111111;

                            match mode {
                                0b0000000 => {
                                    // SLLIW
                                    let shamt = inst.imm & 0b11111;
                                    self.set_reg(inst.rd, (rs1 << shamt) as i32 as i64 as u64);
                                }
                                _ => unreachable!(),
                            }
                        }
                        0b101 => {
                            let mode = (inst.imm >> 5) & 0b1111111;

                            match mode {
                                0b0000000 => {
                                    // SRLIW
                                    let shamt = inst.imm & 0b11111;
                                    self.set_reg(inst.rd, (rs1 >> shamt) as i32 as i64 as u64)
                                }
                                0b0100000 => {
                                    // SRAIW
                                    let shamt = inst.imm & 0b11111;
                                    self.set_reg(inst.rd, ((rs1 as i32) >> shamt) as i64 as u64);
                                }
                                _ => unreachable!(),
                            }
                        }
                        _ => unreachable!(),
                    }
                }
                _ => unimplemented!("Unhandled opcode {:#09b}\n", opcode),
            }

            // Update PC to the next instruction
            self.set_reg(Register::Pc, pc.wrapping_add(4));
        }
    }
}

#[derive(Clone, Copy, Debug)]
/// Reasons why the VM exited
pub enum VmExit {
    /// The VM exited due to a syscall instruction
    Syscall,

    /// The VM exited cleanly as requested by the VM
    Exit,

    /// An integer overflow occured during a syscall due to bad supplied
    /// arguments by the program
    SyscallIntegerOverflow,

    /// A read or write memory request overflowed the address size
    AddressIntegerOverflow,

    /// The address requested was not in bounds of the guest memory space
    AddressMiss(VirtAddr, usize),

    /// An read of `VirtAddr` failed due to missing permissions
    ReadFault(VirtAddr),

    /// An write of `VirtAddr` failed due to missing permissions
    WriteFault(VirtAddr),
}

// 64-bit riscv registers
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum Register {
    Zero = 0,
    Ra,
    Sp,
    Gp,
    Tp,
    T0,
    T1,
    T2,
    S0,
    S1,
    A0,
    A1,
    A2,
    A3,
    A4,
    A5,
    A6,
    A7,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
    S10,
    S11,
    T3,
    T4,
    T5,
    T6,
    Pc,
}

/// R-type
#[derive(Debug)]
struct Rtype {
    funct7: u32,
    rs2: Register,
    rs1: Register,
    funct3: u32,
    rd: Register,
}

impl From<u32> for Rtype {
    fn from(inst: u32) -> Self {
        Rtype {
            funct7: (inst >> 25) & 0b1111111,
            rs2: Register::try_from((inst >> 20) & 0b11111).unwrap(),
            rs1: Register::try_from((inst >> 15) & 0b11111).unwrap(),
            funct3: (inst >> 12) & 0b111,
            rd: Register::try_from((inst >> 7) & 0b11111).unwrap(),
        }
    }
}

/// S-type
#[derive(Debug)]
struct Stype {
    imm: i32,
    rs2: Register,
    rs1: Register,
    funct3: u32,
}

impl From<u32> for Stype {
    fn from(inst: u32) -> Self {
        let imm115 = (inst >> 25) & 0b1111111;
        let imm40 = (inst >> 7) & 0b11111;

        let imm = (imm115 << 5) | imm40;
        let imm = ((imm as i32) << 20) >> 20;

        Stype {
            imm: imm,
            rs2: Register::try_from((inst >> 20) & 0b11111).unwrap(),
            rs1: Register::try_from((inst >> 15) & 0b11111).unwrap(),
            funct3: (inst >> 12) & 0b111,
        }
    }
}

/// J-type
#[derive(Debug)]
struct Jtype {
    imm: i32,
    rd: Register,
}

impl From<u32> for Jtype {
    fn from(inst: u32) -> Self {
        let imm20 = (inst >> 31) & 1;
        let imm101 = (inst >> 21) & 0b1111111111;
        let imm11 = (inst >> 20) & 1;
        let imm1912 = (inst >> 12) & 0b11111111;

        let imm = (imm20 << 20) | (imm1912 << 12) | (imm11 << 11) | (imm101 << 1);
        let imm = ((imm as i32) << 11) >> 11;

        Jtype {
            imm: imm,
            rd: Register::try_from((inst >> 7) & 0b11111).unwrap(),
        }
    }
}

/// B-type
#[derive(Debug)]
struct Btype {
    imm: i32,
    rs2: Register,
    rs1: Register,
    funct3: u32,
}

impl From<u32> for Btype {
    fn from(inst: u32) -> Self {
        let imm12 = (inst >> 31) & 1;
        let imm105 = (inst >> 25) & 0b111111;
        let imm41 = (inst >> 8) & 0b1111;
        let imm11 = (inst >> 7) & 1;

        let imm = (imm12 << 12) | (imm11 << 11) | (imm105 << 5) | (imm41 << 1);
        let imm = ((imm as i32) << 19) >> 19;

        Btype {
            imm: imm,
            rs2: Register::try_from((inst >> 20) & 0b11111).unwrap(),
            rs1: Register::try_from((inst >> 15) & 0b11111).unwrap(),
            funct3: (inst >> 12) & 0b111,
        }
    }
}

/// I-type
#[derive(Debug)]
struct Itype {
    imm: i32,
    rs1: Register,
    funct3: u32,
    rd: Register,
}

impl From<u32> for Itype {
    fn from(inst: u32) -> Self {
        let imm = (inst as i32) >> 20;
        Itype {
            imm: imm,
            rs1: Register::try_from((inst >> 15) & 0b11111).unwrap(),
            funct3: (inst >> 12) & 0b111,
            rd: Register::try_from((inst >> 7) & 0b11111).unwrap(),
        }
    }
}

/// U-type
#[derive(Debug)]
struct Utype {
    imm: i32,
    rd: Register,
}

impl From<u32> for Utype {
    fn from(inst: u32) -> Self {
        Utype {
            imm: (inst & !0xfff) as i32,
            rd: Register::try_from((inst >> 7) & 0b11111).unwrap(),
        }
    }
}

fn main() {
        let mut emu = Emulator::new(48 * 1024 * 1024);
    emu.memory
        .load(
            "./hello-riscv",
            &[
                Section {
                    file_off: 0x0000000000000000,
                    virt_addr: VirtAddr(0x0000000000010000),
                    file_size: 0x00000000000001e8,
                    mem_size: 0x00000000000001e8,
                    permissions: Perm(PERM_READ),
                },
                Section {
                    file_off: 0x00000000000001e8,
                    virt_addr: VirtAddr(0x00000000000111e8),
                    file_size: 0x00000000000020c8,
                    mem_size: 0x00000000000020c8,
                    permissions: Perm(PERM_EXEC),
                },
                Section {
                    file_off: 0x00000000000022b0,
                    virt_addr: VirtAddr(0x00000000000142b0),
                    file_size: 0x0000000000000100,
                    mem_size: 0x0000000000000758,
                    permissions: Perm(PERM_READ | PERM_WRITE),
                },
            ],
        )
        .expect("failed to load test application into address space");

    // set entry point
    emu.set_reg(Register::Pc, 0x111e8);

    // Set up a stack
    let stack = emu
        .memory
        .allocate(32 * 1024)
        .expect("Failed to allocate stack");
    emu.set_reg(Register::Sp, stack.0 as u64 + 32 * 1024);

    // Set up the program name
    let argv = emu
        .memory
        .allocate(8)
        .expect("Failed to allocate program name");
    emu.memory
        .write_from(argv, b"test\0")
        .expect("Failed to write program name");

    macro_rules! push {
        ($expr:expr) => {
            let sp = emu.get_reg(Register::Sp) - core::mem::size_of_val(&$expr) as u64;
            emu.memory
                .write(VirtAddr(sp as usize), $expr)
                .expect("Push failed");
            emu.set_reg(Register::Sp, sp);
        };
    }

    // Set up the initial program stack state
    push!(0u64); // Auxp
    push!(0u64); // Envp
    push!(0u64); // Argv end
    push!(argv.0); // Argv
    push!(1u64); // Argc

    // emu.run().expect("something happened while running the loaded program")


    // Start a timer
    let start = Instant::now();

    // default stats structure
    let mut stats = Arc::new(Statistics::default());

    let emu = Arc::new(emu);

    const THREADS: usize = 4;

    dbg!(THREADS);
    for _ in 0..THREADS {
        let stats = Arc::clone(&stats);
        // Now, fork the VM
        let emulator = emu.fork();
        let parent = Arc::clone(&emu);
        std::thread::spawn(move || {
            worker(emulator, parent, stats);
        });
    }

    use std::time::{Duration, Instant};
    loop {
        std::thread::sleep(Duration::from_millis(1000));
        let fuzz_cases = stats.fuzz_cases.load(Ordering::Relaxed) as u64;
        let elapsed = start.elapsed().as_secs_f64();

        print!(
            "fps {:10.2}\n",
            fuzz_cases as f64 / elapsed
        );
    }

}

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
/// gathering some stats
#[derive(Default)]
struct Statistics {
    fuzz_cases: AtomicU64,
}

fn worker(mut emu: Emulator, original: Arc<Emulator>, stats: Arc<Statistics>) {
    loop {
        // Reset emu to original state
        emu.reset(&*original);

        let vmexit = loop {
            let vmexit = emu.run().expect_err("Failed to execute emulator");

            match vmexit {
                VmExit::Syscall => {
                    if let Err(vmexit) = handle_syscall(&mut emu) {
                        break vmexit;
                    }

                    // Advance PC
                    let pc = emu.get_reg(Register::Pc);
                    emu.set_reg(Register::Pc, pc.wrapping_add(4));
                }
                _ => break vmexit,
            }
        };

        // print!("VM exited with {:#x?}\n", vmexit);

        stats.fuzz_cases.fetch_add(1, Ordering::Relaxed);

    }
}

fn handle_syscall(emu: &mut Emulator) -> Result<(), VmExit> {
    // Get the syscall number
    let num = emu.get_reg(Register::A7);

    match num {
        96 => {
            // set_tid_address(), just return the TID
            emu.set_reg(Register::A0, 1337);
            Ok(())
        }
        29 => {
            // ioctl()
            emu.set_reg(Register::A0, !0);
            Ok(())
        }
        66 => {
            // writev()
            let fd = emu.get_reg(Register::A0);
            let iov = emu.get_reg(Register::A1);
            let iovcnt = emu.get_reg(Register::A2);

            // We currently only handle stdout and stderr
            if fd != 1 && fd != 2 {
                // Return error
                emu.set_reg(Register::A0, !0);
                return Ok(());
            }

            let mut bytes_written = 0;

            for idx in 0..iovcnt {
                // Compute the pointer to the IO vector entry
                // corresponding to this index and validate that it
                // will not overflow pointer size for the size of
                // the `_iovec`
                let ptr = 16u64
                    .checked_mul(idx)
                    .and_then(|x| x.checked_add(iov))
                    .and_then(|x| x.checked_add(15))
                    .ok_or(VmExit::SyscallIntegerOverflow)? as usize
                    - 15;

                // Read the iovec entry pointer and length
                let buf: usize = emu.memory.read(VirtAddr(ptr + 0))?;
                let len: usize = emu.memory.read(VirtAddr(ptr + 8))?;

                // Look at the buffer!
                let data = emu.memory.peek_perms(VirtAddr(buf), len, Perm(PERM_READ))?;

                if VERBOSE_PRINTS {
                    if let Ok(st) = core::str::from_utf8(data) {
                        print!("{}", st);
                    }
                }

                // Update number of bytes written
                bytes_written += len as u64;
            }

            // Return number of bytes written
            emu.set_reg(Register::A0, bytes_written);
            Ok(())
        }
        94 => Err(VmExit::Exit),
        _ => {
            panic!("Unhandled syscall {}\n", num);
        }
    }
}
