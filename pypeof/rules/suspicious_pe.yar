rule Suspicious_UPX_Packed {
    meta:
        description = "Detects UPX packed executables"
        author = "pypeof"
        severity = "medium"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
        $upx_sig = { 55 50 58 21 0D 09 02 07 }
    condition:
        uint16(0) == 0x5A4D and (($upx0 and $upx1) or $upx2 or $upx_sig)
}

rule Suspicious_Section_Names {
    meta:
        description = "Detects non-standard or packer-associated section names"
        author = "pypeof"
        severity = "medium"
    strings:
        $s1 = ".themida" ascii
        $s2 = ".vmp0" ascii
        $s3 = ".vmp1" ascii
        $s4 = ".nsp0" ascii
        $s5 = ".nsp1" ascii
        $s6 = "MEW" ascii
        $s7 = ".aspack" ascii
        $s8 = ".adata" ascii
        $s9 = "PEC2" ascii
        $s10 = ".petite" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Suspicious_Debug_Artifacts {
    meta:
        description = "Detects suspicious PDB paths or debug artifacts"
        author = "pypeof"
        severity = "low"
    strings:
        $pdb1 = /[A-Z]:\\(Users|users)\\[^\\]{1,32}\\(Desktop|Documents)\\.*\.pdb/ ascii nocase
        $pdb2 = /[A-Z]:\\(Temp|tmp)\\.*\.pdb/ ascii nocase
        $pdb3 = "Release\\" ascii
        $pdb4 = "Debug\\" ascii
    condition:
        uint16(0) == 0x5A4D and any of ($pdb*)
}
