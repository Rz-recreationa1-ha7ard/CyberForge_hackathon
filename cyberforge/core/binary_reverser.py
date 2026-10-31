"""
Autonomous Binary Reverse-Engineering Engine (FR-3 / FR-4 Extension).

Performs dynamic in-memory ELF64 parsing, disassembly of check routines,
and cryptographic keystream inversion to recover service authentication passkeys
without human intervention.
"""

import logging
from typing import Optional, Tuple

logger = logging.getLogger("BinaryReverser")


def solve_elf_validation_routine(elf_bytes: bytes) -> Optional[str]:
    """
    Parses a Linux ELF64 binary, disassembles the validation loop in .text,
    extracts the ciphertext and key tables from .rodata, and computes the
    inverse keystream to reconstruct the passkey dynamically.
    """
    if len(elf_bytes) < 64 or elf_bytes[:4] != b"\x7fELF":
        logger.debug("Provided payload is not a valid ELF binary.")
        return None

    try:
        # 1. Parse ELF64 Section Headers
        e_shoff = int.from_bytes(elf_bytes[40:48], "little")
        e_shentsize = int.from_bytes(elf_bytes[58:60], "little")
        e_shnum = int.from_bytes(elf_bytes[60:62], "little")
        e_shstrndx = int.from_bytes(elf_bytes[62:64], "little")

        shstr_hdr = elf_bytes[e_shoff + e_shstrndx * e_shentsize : e_shoff + (e_shstrndx + 1) * e_shentsize]
        shstr_off = int.from_bytes(shstr_hdr[24:32], "little")

        sections = {}
        for i in range(e_shnum):
            sh = elf_bytes[e_shoff + i * e_shentsize : e_shoff + (i + 1) * e_shentsize]
            name_idx = int.from_bytes(sh[0:4], "little")
            name = elf_bytes[shstr_off + name_idx :].split(b"\0")[0].decode("ascii", errors="ignore")
            offset = int.from_bytes(sh[24:32], "little")
            size = int.from_bytes(sh[32:40], "little")
            addr = int.from_bytes(sh[16:24], "little")
            sections[name] = (addr, offset, size)

        if ".text" not in sections or ".rodata" not in sections:
            logger.debug("ELF binary missing .text or .rodata sections.")
            return None

        text_addr, text_off, text_size = sections[".text"]
        rodata_addr, rodata_off, rodata_size = sections[".rodata"]

        text = elf_bytes[text_off : text_off + text_size]
        rodata = elf_bytes[rodata_off : rodata_off + rodata_size]

        # 2. Disassemble .text opcodes to identify the keystream loop
        # Pattern: mov ecx, <init> -> 0xb9
        mov_ecx_idx = text.find(b"\xb9")
        if mov_ecx_idx == -1:
            return None
        init_ecx = int.from_bytes(text[mov_ecx_idx + 1 : mov_ecx_idx + 5], "little")

        # Pattern: add ecx, <step> -> 0x83 0xc1 <step>
        add_ecx_idx = text.find(b"\x83\xc1")
        if add_ecx_idx == -1:
            return None
        step_ecx = text[add_ecx_idx + 2]

        # Pattern: cmp rax, <pass_len> -> 0x48 0x83 0xf8 <len>
        cmp_len_idx = text.find(b"\x48\x83\xf8", add_ecx_idx)
        pass_len = text[cmp_len_idx + 3] if cmp_len_idx != -1 else 16

        # Pattern: movzx edx, byte ptr [rax + <addr_b>] -> 0x0f 0xb6 0x90 <disp32>
        mov_b_idx = text.find(b"\x0f\xb6\x90")
        if mov_b_idx == -1:
            return None
        addr_b = int.from_bytes(text[mov_b_idx + 3 : mov_b_idx + 7], "little")
        off_b = addr_b - rodata_addr

        # Pattern: xor dl, byte ptr [rsi + <addr_a>] -> 0x32 0x96 <disp32>
        xor_a_idx = text.find(b"\x32\x96")
        if xor_a_idx == -1:
            return None
        addr_a = int.from_bytes(text[xor_a_idx + 2 : xor_a_idx + 6], "little")
        off_a = addr_a - rodata_addr

        table_b = rodata[off_b : off_b + pass_len]
        table_a = rodata[off_a : off_a + 8]  # Masked with i & 7

        # 3. Dynamic Keystream Inversion
        ecx = init_ecx
        recovered = []
        for i in range(pass_len):
            ch = table_b[i] ^ (ecx & 0xFF) ^ table_a[i % len(table_a)]
            recovered.append(ch)
            ecx = (ecx + step_ecx) & 0xFF

        passkey = bytes(recovered).decode("ascii")
        logger.info(f"BinaryReverser: Dynamically recovered passkey: '{passkey}' from ELF artifact")
        return passkey

    except Exception as exc:
        logger.debug(f"BinaryReverser encountered parsing exception: {exc}")
        return None

