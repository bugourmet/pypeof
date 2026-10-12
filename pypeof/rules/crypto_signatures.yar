rule Contains_Base64_PE {
    meta:
        description = "Detects Base64-encoded PE files embedded in the binary"
        author = "pypeof"
        severity = "high"
    strings:
        $b64_mz = "TVqQAAMAAAA" ascii wide  // Base64 of MZ header
        $b64_mz2 = "TVpQAAIAAAA" ascii wide
        $b64_mz3 = "TVoAAAAAAAA" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Contains_XOR_Loop {
    meta:
        description = "Detects potential XOR decryption loops commonly used for payload decoding"
        author = "pypeof"
        severity = "medium"
    strings:
        $xor_loop1 = { 80 3? ?? 74 ?? 80 3? ?? 74 ?? 30 }  // cmp + jz + xor pattern
        $xor_loop2 = { 31 ?? 83 C? 01 3B ?? 7? }  // xor reg,reg; add reg,1; cmp; jl
        $xor_loop3 = { 32 ?? 88 ?? 4? 83 ?? 00 75 }  // xor al; mov []; dec; cmp 0; jnz
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Embedded_PE_File {
    meta:
        description = "Detects embedded PE file within the binary"
        author = "pypeof"
        severity = "high"
    strings:
        $mz = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and #mz > 1
}
