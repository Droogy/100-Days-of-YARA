import "pe"
import "hash"
import "math"
import "time"
import "elf"

rule CVE_2021_4034 {
    meta:
        description = " 'Pwnkit' exploit first seen by @bl4sty on Twitter and outlined by Qualys "
        author = "Droogy"
        DaysOfYARA = "9/100"

    strings:
        $s1 = "maybe get shell now?" wide ascii
        $s2 = "compile helper.." wide ascii
        $s3 = "gcc -o" wide ascii
        $h1 = { 48 83 ec 08 48 83 c4 08 c3 }	// sub RSP, 0x8
        $h2 = { e8 31 fd ff ff c9 c3 55 48 89 e5 48 81 ec 00 01 ?? ?? 89 bd ?? ff ff ff 48 89 b5 00 ff ff ff 64 48 8b 04 25 ?? ?? ?? ?? 48 89 45 ?? 31 c0 48 c7 85 ?? ff ff ff ?? ?? ?? ?? 48 8d 05 ?? ?? ?? ?? 48 89 85 ?? ff ff ff 48 8d 05 ?? ?? ?? ?? 48 89 85 ?? ff ff ff 48 8d 05 ?? ?? ?? ?? 48 89 85 ?? ff ff ff 48 8d 05 ?? ?? ?? ?? ?? 89 85 48 ff ff ff 48 c7 85 ?? ff ff ff ?? ?? ?? ?? 48 8d 3d ?? ?? ?? ?? e8 7e fc ff ff b8 ?? ?? ?? ?? e8 80 fe ff ff 48 8d 85 ?? ff ff ff 48 89 c6 48 8d 3d ?? ?? ?? ?? e8 ce 01 ?? ?? 85 c0 79 64 }

    condition:
        uint16(0) == 0x457f and
        elf.type == elf.ET_EXEC and
        elf.number_of_sections > 20 and
        filesize < 15000 and
        all of ($h*) and
        //validates 1st occurence of s1 is within 100 bytes of s2
        (1 of ($s*)) or (@s2[1] - @s1[1] < 100)

}

rule MBR_Wiper {
    meta:
        description = " Look for MBR wiper referenced by MSTIC which is used by DEV-0586 "
        author = "Droogy"
        DaysOfYARA = "8/100"

    strings:
        $s1 = "GCC: (GNU) 6.3.0" wide ascii
        $s2 = "You should pay us  $10k via bitcoin wallet" wide ascii
        $s3 = "tox ID" wide ascii
        $s4 = "In case you want to recover all hard drives" wide ascii

    condition:
        uint16(0) == 0x5a4d and
        3 of ($s*) and
        pe.imports("KERNEL32.dll") >= 20
}

rule rtfDocumentWithObject {
    meta:
        description = " Identify RTF files with embedded objects "
        author = "Droogy"
        DaysOfYARA = "7/100"
    
    strings:
        $s1 = "\\object" nocase ascii wide
    
    condition:
        uint32(0) == 0x74725c7b     /* {\rt */
        and $s1
}

rule embeddedDocfile {
    meta:
        description = " look for embedded microsoft docfile header "
        author = "Droogy"
        DaysOfYARA = "7/100"

    strings:
        $s1 = { D0 CF 11 E0 }

    condition:
        $s1 in (100..filesize)

}

rule Amadey_Trojan {
    meta:
        description = " Identify Amadey Trojan using a binary trait (courtesy of binlex) and a few strings"
        author = "Droogy"
        DaysOfYARA = "6/100"

    strings:
        $trait = {8b 8d ?? ff ff ff 42 8b c1 81 fa 00 10 ?? ?? 72 14}
        $s1 = "PPPPP" nocase wide ascii
        $s2 = "Y_^[" nocase wide ascii
        $s3 = "8\\u0" nocase wide ascii
    
    condition:
        uint16(0) == 0x5a4d and
        $trait and 2 of ($s*)
}

rule unreliableTimestamp {
    meta:
        description = " Parse .debug section in PE files and look for evidence that a PE file may have unreliable timestamps"
        author = "Droogy"
        DaysOfYARA = "5/100"

    condition:
        pe.is_pe
        and
        pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].virtual_address != 0
        and
        pe.timestamp > time.now()
}

rule backdooredChromeMiner {
    meta:
        description = " Look for strings indicative of a backdoored version of Chrome with a coin miners"
        author = "Droogy"
        DaysOfYARA = "4/100"

    strings:
        $s1 = "chrome.exe" ascii wide nocase
        $c1 = "xmrig" ascii wide nocase
        $c2 = "coinhive" ascii wide nocase
        $c3 = "hashvault.pro" ascii wide nocase

    condition:
        $s1 and 1 of ($c*)
}

rule packedTextSection {
    meta:
        description = " Look for high-entropy .text sections within PE files "
        author = "Droogy"
        DaysOfYARA = "3/100"

    condition:
        for any section in pe.sections: (
            section.name == ".text"    // .text section contains executable code likely to be packed
        )
        and
        for any section in pe.sections: (
            math.entropy(
                section.raw_data_offset, 
                section.raw_data_size
            ) >= 7    // entropy goes from 0-8, generally 6.5 and above is high
        )
}

rule isDotNet {
    meta:
        description = " Detect if file is .NET assembly "
        author = "Droogy"
        DaysOfYARA = "2/100"

    condition:
        pe.number_of_sections >= 3
        and
        pe.imports(/mscoree.dll/i, /_CorExeMain/ ) == 1
}

rule solitaire {
    meta:
        description = " Suspicious file pulled from malshare named Solitaire.exe - has no hits on VT"
        author = "Droogy"
        DaysOfYARA = "1/100"
    
    condition:
        uint16(0) == 0x5a4d
        and
        pe.number_of_sections == 7 
        and
        for any var_section in pe.sections: (
            var_section.name == "_RDATA"    // clue this is a cpp file compiled in VS
        )
}
