rule suspicious_pe_characteristics {
    meta:
        description = "Detects suspicious PE file characteristics"
        author = "MalwareAnalyzer"
        date = "2024"
    
    strings:
        $mz = "MZ"
        $pe = "PE\x00\x00"
        $suspicious_imports = /CreateProcess|WriteProcessMemory|VirtualAlloc|LoadLibrary|GetProcAddress/
    
    condition:
        $mz at 0 and $pe in (0..1024) and $suspicious_imports
}

rule packed_executable {
    meta:
        description = "Detects packed executables"
        author = "MalwareAnalyzer"
        date = "2024"
    
    strings:
        $upx = "UPX"
        $aspack = "ASPack"
        $fsg = "FSG!"
    
    condition:
        any of them
}

rule suspicious_strings {
    meta:
        description = "Detects suspicious strings in files"
        author = "MalwareAnalyzer"
        date = "2024"
    
    strings:
        $cmd = "cmd.exe" nocase
        $powershell = "powershell" nocase
        $http = "http://" nocase
        $https = "https://" nocase
        $ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
    
    condition:
        any of them
} 