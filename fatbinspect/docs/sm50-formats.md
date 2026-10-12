# NVIDIA sm_50 (Maxwell) fatbin & cubin header reference

Scope: 64-bit little-endian Linux, CUDA ≤ 12.x (ELF ABI v7). sm_50 support was
removed in CUDA 13, so the ABI v8 layout (sm in `e_flags` bits 8–15, `EI_OSABI` 0x41)
never applies to sm_50.

Confidence tags:
- **[NV]**: NVIDIA public header (`/usr/include/fatbinary_section.h`) or NVIDIA tool output.
- **[LLVM]**: `llvm/BinaryFormat/ELF.h`.
- **[EXP]**: checked locally against nvcc/fatbinary 12.4 output (see "Verification").
- **[COMM]**: community reverse engineering, not independently verified.

---

## 1. Host ELF → fatbin

| Section | Contents |
|---|---|
| `.nvFatBinSegment` (`WA`) | array of `__fatBinC_Wrapper_t`, one per translation unit / link stub **[NV]** |
| `.nv_fatbin` (`A`) | the fatbin blobs, each 8-byte aligned **[NV][EXP]** |
| `__nv_relfatbin` | pre-linked relocatable fatbin data (`-rdc`) **[NV]** |
| `__nv_module_id` | module-id string **[EXP]** |

### 1.1 `__fatBinC_Wrapper_t` (24 bytes) **[NV]**

| Off | Type | Field | Notes |
|---|---|---|---|
| 0x00 | u32 | magic | `0x466243B1` (`FATBINC_MAGIC`, bytes `b1 43 62 46`) |
| 0x04 | u32 | version | `1` = `FATBINC_VERSION`, `2` = `FATBINC_LINK_VERSION` |
| 0x08 | u64 | data | **virtual address** of the fatbin header |
| 0x10 | u64 | filename_or_fatbins | v1: offline filename; v2: array of prelinked fatbins |

Notes **[EXP]**:
- `data` is a VA. In PIE executables it is an `R_X86_64_RELATIVE` relocation. GNU ld
  also stores the addend in place, so the file value is usable. lld and other linkers
  may store 0 there, in which case the value has to come from `.rela.dyn`.
- Map VA → file offset through `PT_LOAD` (or `sh_addr - sh_offset` of the containing
  section). They happen to be equal in GNU ld PIE output, but non-PIE output starts at
  0x400000.
- A plain nvcc 12.4 build emits **two** wrappers: a v2 link stub, whose fatbin holds a
  tiny cubin with no `.text`, and a v1 wrapper for the real module.
- Scan `.nv_fatbin` for consecutive fatbin headers (magic `0xBA55ED50`, 8-byte
  aligned) as well. Not every fatbin has a wrapper: in libnvjpeg 12.3 the first of 11
  fatbins (at the start of `.nv_fatbin`) has none, and cuobjdump still lists it.

## 2. Fatbin

### 2.1 Fatbin header (16 bytes)

| Off | Type | Field | Value |
|---|---|---|---|
| 0x00 | u32 | magic | `0xBA55ED50` **[EXP]**. Old-style fatbin magic `0x1EE55A01` is pre-CUDA-4 **[COMM]** |
| 0x04 | u16 | version | `1` |
| 0x06 | u16 | header_size | `0x10`. Entries start at `hdr + header_size` |
| 0x08 | u64 | fat_size | bytes of entries **after** the header. The next fatbin starts at `hdr + header_size + fat_size` |

Iterate entries while `off < hdr + header_size + fat_size` (strict `<`).

### 2.2 Entry header (`header_size` bytes: 0x48 for ELF, 0x58 for PTX)

| Off | Type | Field | Notes |
|---|---|---|---|
| 0x00 | u16 | kind | `1` PTX, `2` ELF (cubin) **[EXP]**. `4` = old cubin **[COMM]**. Other values (e.g. LTO-IR) are for later toolkits **[COMM]** |
| 0x02 | u16 | version | `0x0101` **[EXP]** |
| 0x04 | u32 | header_size | the payload starts at `entry + header_size` **[EXP]** |
| 0x08 | u64 | padded_payload_size | next entry = `entry + header_size + padded_payload_size` **[EXP]** |
| 0x10 | u32 | compressed_size | size of the stored compressed payload. **0 if uncompressed** **[EXP]** |
| 0x14 | u32 | options_desc_offset | entry-relative offset of the ptxas-options descriptor (PTX: `0x48`), else 0 **[EXP]** |
| 0x18 | u16 | minor | PTX: PTX ISA minor (12.4 → 4). ELF: `7` **[EXP]** |
| 0x1A | u16 | major | PTX: PTX ISA major (12.4 → 8). ELF: `1` **[EXP]** |
| 0x1C | u32 | arch | SM number, decimal (`50` = `0x32`) **[EXP]** |
| 0x20 | u32 | ident_offset | entry-relative offset of the identifier string (`--ident`), 0 = none **[EXP]** |
| 0x24 | u32 | ident_len | length without NUL **[EXP]** |
| 0x28 | u64 | flags | see 2.3 |
| 0x30 | u64 | reserved | 0 **[EXP]** |
| 0x38 | u64 | uncompressed_size | decompressed payload size. **0 if uncompressed** **[EXP]** |
| 0x40 | … | variable area | identifier (NUL-padded to 8) and, for PTX, the options descriptor **[EXP]** |

PTX options descriptor (at `entry + options_desc_offset`) **[EXP]**:
`u32 options_offset` (entry-relative), `u32 options_len`, then the options string
(`fatbinary --cmdline`, i.e. `-Xptxas` flags), NUL-padded to 8.

Worked example (`fatbinary --ident=myident --cmdline="-O1 -v"`, PTX entry):
`0x40 "myident\0" · 0x48 {0x50, 6} · 0x50 "-O1 -v\0\0"` → payload at 0x58.

Payload bytes:
- uncompressed: `padded_payload_size` bytes. A cubin's real size comes from its ELF
  header (`e_shoff + e_shnum*e_shentsize`, or the max of section/phdr ends).
- compressed: the first `compressed_size` bytes, decompressed to `uncompressed_size`.

### 2.3 Entry flags (u64 at +0x28)

| Bit | Meaning | Source |
|---|---|---|
| `0x0001` | 64-bit address | EXP |
| `0x0002` | debug (`-g`) | EXP |
| `0x0010` | Linux host | EXP |
| `0x0020` | macOS host | COMM |
| `0x0040` | Windows host | COMM |
| `0x1000` | zlib compression | COMM |
| `0x2000` | LZ4 compression (CUDA 11–12 default) | EXP |
| `0x4000` | LZ4 variant ("LZ4Compression2") | COMM |
| `0x8000` | Zstd compression (CUDA 12.8+/13) | COMM |

Observed with nvcc 12.4 sm_50: PTX is always `0x2011` (compressed by default). ELF is
`0x11` (raw) unless `-Xfatbin -compress-all` is used, which gives `0x2011`.

### 2.4 LZ4 payload **[EXP][COMM]**

A standard **LZ4 raw block** (no frame header). The token byte's high nibble is the
literal length and its low nibble + 4 is the match length; a nibble of 15 extends the
length with following bytes. A u16 LE back-offset follows. The decompressed data starts
with `7f 45 4c 46` for ELF and `//` for PTX. Any LZ4 block decoder works
(`lz4_flex::block::decompress(buf, uncompressed_size)`).

## 3. Cubin (ELF) for sm_50

### 3.1 ELF header

| Field | Value | Source |
|---|---|---|
| `e_ident` | `7f 45 4c 46 02 01 01 33 07 …` | EXP |
| `EI_CLASS` | 2 (ELF64). 32-bit cubins exist for `-m32` (legacy) | EXP |
| `EI_OSABI` | `0x33` = 51 = `ELFOSABI_CUDA` | LLVM, EXP |
| `EI_ABIVERSION` | `7` = `ELFABIVERSION_CUDA_V1` | LLVM, EXP |
| `e_type` | `ET_EXEC` (2) normally, `ET_REL` (1) with `-rdc` / `-c` device objects | EXP |
| `e_machine` | `190` (0xBE) = `EM_CUDA` | LLVM, EXP |
| `e_version` | **CUDA toolkit version ×10 + minor**, e.g. `0x7c` = 124 = CUDA 12.4. cuobjdump prints this as "toolkit=124" | NV, EXP |
| `e_entry` | 0 | EXP |
| `e_flags` | see 3.2 | |

### 3.2 `e_flags` (ABI v7) **[LLVM][EXP]**

| Mask | Name | sm_50 value |
|---|---|---|
| `0x000000FF` | `EF_CUDA_SM` (real arch) | `0x32` = 50 |
| `0x00000100` | `EF_CUDA_TEXMODE_UNIFIED` | set |
| `0x00000200` | `EF_CUDA_TEXMODE_INDEPENDANT` | — |
| `0x00000400` | `EF_CUDA_64BIT_ADDRESS` | set |
| `0x00000800` | `EF_CUDA_ACCELERATORS_V1` (sm_90a only) | — |
| `0x00001000` | `EF_CUDA_SW_FLAG_V2` | — |
| `0x00FF0000` | `EF_CUDA_VIRTUAL_SM` (PTX arch it was compiled from) | `0x32` |

Typical sm_50 value: **`0x00320532`**. For other arches the `EF_CUDA_SM*` value is the
SM number (sm_52 = 0x34, sm_53 = 0x35, …).

### 3.3 Section types (`SHT_LOPROC` = 0x70000000 base) **[NV tool names][EXP]**

| Value | cuobjdump name | Section |
|---|---|---|
| `0x70000000` | `CUDA_INFO` | `.nv.info`, `.nv.info.<fn>` |
| `0x70000001` | `CUDA_CALLGRAPH` | `.nv.callgraph` (entsize 8) |
| `0x7000000A` | `CUDA_SHARED` | `.nv.shared.<fn>` in `ET_REL` (`-rdc`) cubins. No file data, like `NOBITS` (`ET_EXEC` uses `NOBITS`) **[EXP]** |
| `0x7000000B` | `CUDA_RELOCINFO` | `.nv.rel.action` |
| `0x70000064 + n` | `CUDA_CONSTANT_Bn` | `.nv.constantN` in `ET_REL` (`-rdc`) cubins. `ET_EXEC` cubins use `PROGBITS` **[EXP]** |

### 3.4 Sections in a typical sm_50 cubin **[EXP]**

| Name | Type | Flags | `sh_link` / `sh_info` |
|---|---|---|---|
| `.shstrtab`, `.strtab`, `.symtab` | standard | | |
| `.nv.info` | CUDA_INFO | | link=`.symtab` |
| `.nv.info.<fn>` | CUDA_INFO | `SHF_INFO_LINK` | info = index of `.text.<fn>` |
| `.nv.constant0.<fn>` | PROGBITS | `A`+`I` | info = `.text.<fn>`. Kernel params at **0x140** (sm_5x driver area is 0x000–0x13F) |
| `.nv.constant2` / `3` / `4` | PROGBITS | `A` | bank 3 = `__constant__` user data, bank 4 = 64-bit addresses of globals (relocated by `.rel.nv.constant4`) |
| `.text.<fn>` | PROGBITS | `AX` + barriers | see 3.5 |
| `.nv.global.init` / `.nv.global` | PROGBITS / NOBITS | `WA` | initialised / zero `__device__` vars |
| `.nv.shared.<fn>` | NOBITS | `WA`+`I` | static `__shared__`, info = `.text.<fn>` |
| `.nv.local.<fn>` | NOBITS | | local memory (spills) |
| `.rel.*` / `.rela.*` | REL / RELA | | `R_CUDA_*` relocations |
| `.debug_*`, `.nv_debug_*` | | | with `-G` / `-lineinfo` |

### 3.5 `.text.<fn>`: the "kernel raw binary" **[EXP]**

- Bytes: `file[sh_offset .. sh_offset + sh_size]`. `sh_addralign` = 32.
- **`sh_info` = (register_count << 24) | symbol_index_of_function** (e.g. `0x0A00000E`
  → 10 regs, symbol 14). readelf warns about this; it is expected. Seen on sm_50–sm_89;
  **sm_90 (12.4) leaves the register bits 0**. `EIATTR_REGCOUNT` in `.nv.info` is what
  cuobjdump reports, on every arch **[EXP]**.
- **`sh_flags` bits 20–26 = number of barriers** (`0x100006` = `AX` + 1 barrier from
  `__syncthreads()`).
- The function symbol has `STT_FUNC`, `STB_GLOBAL`, and **`st_other = 0x10`
  (kernel-entry marker; name unofficial)**. `st_size` = code size.
- Device functions in `-rdc` builds get their own `.text.<fn>` without the 0x10 entry bit.

**Maxwell instruction bundle**: 32 bytes = 1 control word + 3 instructions (each u64 LE).
Control word layout **[COMM, maxas]**: insn i (i = 0..2) uses bits `21*i … 21*i+20`:

| Bits (in 21-bit group) | Field |
|---|---|
| 0–3 | stall cycles (0–15) |
| 4 | yield (**0** = yield) |
| 5–7 | write barrier (7 = none) |
| 8–10 | read barrier (7 = none) |
| 11–16 | wait-barrier mask (6 barriers) |
| 17–20 | operand reuse flags |

Bit 63 is unused. Bundle-relative check: `offset % 32 == 0` ⇒ control word. The same
format is used through sm_6x.

Checked against toolkit libraries (libnvjpeg, libcurand, libnppial 12.x, sm_50–sm_61)
**[EXP]**: the reuse bits of 312,486 of 312,488 instructions match the `.reuse` operand
markers of `cuobjdump -sass` exactly, and none has more markers than bits (the 2 extra
bits are on immediate operand slots, which SASS doesn't mark). This confirms the reuse
field and the instruction order within the word (insn 0 in bits 0–20). Barrier fields are
never 6, and e.g. `S2R` sets a write barrier that the consuming instruction waits on.
Stall and yield (and yield's polarity) have no oracle and remain **[COMM]**.

### 3.6 `.nv.info` records **[NV tool names][EXP][COMM]**

Each record is `u8 format, u8 attribute`, followed by:

| Format | Name | Payload |
|---|---|---|
| 1 | `EIFMT_NVAL` | u16 (unused, 0). No value |
| 2 | `EIFMT_BVAL` | u16 value (byte) |
| 3 | `EIFMT_HVAL` | u16 value |
| 4 | `EIFMT_SVAL` | u16 size + `size` bytes |

Attributes seen on sm_50 (12.4) plus common ones:

| Code | Name | Where | Value layout |
|---|---|---|---|
| 0x04 | CTAIDZ_USED | per-fn | NVAL |
| 0x05 | MAX_THREADS | per-fn | SVAL u32×3 |
| 0x0A | PARAM_CBANK | per-fn | u32 sym(`.nv.constant0.<fn>` section sym), u16 offset (0x140), u16 size |
| 0x0F | EXTERNS | per-fn | u32 sym indices |
| 0x10 | REQNTID | per-fn | u32×3 |
| 0x11 | FRAME_SIZE | global | u32 fn sym, u32 bytes |
| 0x12 | MIN_STACK_SIZE | global | u32 fn sym, u32 bytes |
| 0x17 | KPARAM_INFO | per-fn | 12 B: u32 index, u16 ordinal, u16 offset, u32 `{logAlign:8, space:4, cbank:5, isCBank:1, size:14}` (size = `w>>18`) |
| 0x19 | CBANK_PARAM_SIZE | per-fn | HVAL total param bytes |
| 0x1B | MAXREG_COUNT | per-fn | HVAL (0xFF = unlimited) |
| 0x1C | EXIT_INSTR_OFFSETS | per-fn | u32 offsets of `EXIT` instructions |
| 0x1D | S2RCTAID_INSTR_OFFSETS | per-fn | u32 offsets |
| 0x1E | CRS_STACK_SIZE | per-fn | u32 |
| 0x23 | MAX_STACK_SIZE | global | u32 sym, u32 |
| 0x2A | SW1850030_WAR | per-fn | NVAL |
| 0x2F | REGCOUNT | global | u32 fn sym, u32 regs |
| 0x30 | SW2393858_WAR | per-fn | NVAL |
| 0x37 | CUDA_API_VERSION | per-fn | u32 (0x7c = 12.4) |

| 0x28 | COOP_GROUP_INSTR_OFFSETS | per-fn | u32 offsets |
| 0x29 | COOP_GROUP_MASK_REGIDS | per-fn | u32s |
| 0x31 | INT_WARP_WIDE_INSTR_OFFSETS | per-fn | u32 offsets |
| 0x34 | INDIRECT_BRANCH_TARGETS | per-fn | variable |
| 0x35 | SW2861232_WAR | per-fn | NVAL |
| 0x36 | SW_WAR | per-fn | u32 |
| 0x44 | UNUSED_LOAD_BYTE_OFFSET | per-fn | u32s |
| 0x50 | SPARSE_MMA_MASK | per-fn | u32 |

Full code list (0x00–0x50): CuAssembler `CuNVInfo.py`, in `src/decode.rs`. The 24 codes
above (all that occur in libnvjpeg, libnppial, libcurand 12.x, sm_50–sm_90) are checked
against `cuobjdump -elf` record by record by the tests **[EXP]**; the rest are **[COMM]**.
cuobjdump's string table lists the names in a different order, so it can't be used to
derive codes.

`cuobjdump -res-usage` fields **[EXP]**: `REG` = `EIATTR_REGCOUNT`, `STACK` =
`EIATTR_MIN_STACK_SIZE`, `SHARED` = size of `.nv.shared.<fn>`, `LOCAL` = size of
`.nv.local.<fn>`, `CONSTANT[0]` = size of `.nv.constant0.<fn>`.

`PARAM_CBANK` stores offset and size as one u32: `offset | size << 16` (sm_5x: offset
0x140, sm_70+: 0x160).

### 3.7 Program headers (ET_EXEC) **[EXP]**

`PT_PHDR`, then `PT_LOAD R E` (constant banks + `.text.*` + shared), `PT_LOAD RW`
(`.nv.global*`), and a trailing `PT_LOAD` covering the phdr table. All `p_vaddr` = 0;
the driver relocates. The program header table usually sits **after** the section
headers at the end of the file. `ET_REL` cubins have no segments.

---

## Verification

Generated on 2026-10-11 with CUDA 12.4 (`nvcc`, `fatbinary`, `cuobjdump`, `readelf`):

```
nvcc -gencode arch=compute_50,code=[sm_50,compute_50] {-fatbin|-cubin|-o host} k.cu
nvcc ... -Xfatbin -compress-all -fatbin            # LZ4 ELF entry
fatbinary -64 --ident=myident --cmdline="-O1 -v" --image3=kind=ptx,sm=50,file=k.ptx ...
fatbinary -64 -g --compress=false ...              # flags 0x13
```

## Sources

- NVIDIA `fatbinary_section.h` (shipped with the toolkit)
- [LLVM `ELF.h`](https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/ELF.h): `EM_CUDA`, `ELFOSABI_CUDA*`, `EF_CUDA_*`
- [Inside CUDA Fatbins, Part 1 (Stealthium)](https://stealthium.io/blog/fatbins-cuda-gpu-binary-formats-part-1): entry struct, flags table
- [cricket `cpu-elf2.c` (RWTH-ACS)](https://github.com/RWTH-ACS/cricket/blob/master/cpu/cpu-elf2.c): entry struct, LZ4 decoder, EIATTR usage
- [CuAssembler `CuNVInfo.py`](https://github.com/cloudcores/CuAssembler/blob/master/CuAsm/CuNVInfo.py) and [User Guide](https://github.com/cloudcores/CuAssembler/blob/master/UserGuide.md)
- [maxas wiki: Control Codes](https://github.com/NervanaSystems/maxas/wiki/Control-Codes)
- [NVIDIA CUDA Binary Utilities](https://docs.nvidia.com/cuda/cuda-binary-utilities/index.html)
