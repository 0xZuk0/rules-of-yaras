import "hash"
import "pe"

rule WannaCry
{
    meta :
        last_updated = "01-03-2022"
        author = "Zuk0"
        description = "Yara rule to detect wannacry ransomware"
    
    strings :
        $killswitch_domain = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $string1 = "C:\\%s\\qeriuwjhrf" ascii
        $reg_name = "WanaCrypt0r" wide
        $password = "WNcry@2ol7" ascii
        $exe1 = "taskdl.exe" ascii
        $exe2 = "taskse.exe" ascii
        $service_name = "Microsoft Security Center (2.0) Service" ascii

    condition :
        pe.is_pe and
        hash.sha256(0, filesize) == "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c" and
        hash.sha256(204964, 3514368) == "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa" and
        $killswitch_domain and
        $string1 and
        $reg_name and 
        $password and
        $exe1 and
        $exe2 and
        $service_name
}

rule Wannacry_Tasksche
{
    meta :
        last_updated = "01-03-2022"
        author = "Zuk0"
        description = "Yara rule to detect wannacry ransomware"

    condition:
        hash.sha256(0, filesize) == "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa" and
        hash.sha256(65776, 3446325) == "5873c1b5b246c80ab88172d3294140a83d711cd64520a0c7dd7837f028146b80"
}

rule Wannacry_Taskdll
{
    meta :
        last_updated = "01-03-2022"
        author = "Zuk0"
        description = "Yara rule to detect wannacry ransomware"

    condition:
        hash.sha256(0, filesize) == "4a468603fdcb7a2eb5770705898cf9ef37aade532a7964642ecd705a74794b79"
}

rule Wannacry_Taskse
{
    meta :
        last_updated = "01-03-2022"
        author = "Zuk0"
        description = "Yara rule to detect wannacry ransomware"
        
    condition:
        hash.sha256(0, filesize) == "2ca2d550e603d74dedda03156023135b38da3630cb014e3d00b1263358c5f00d"
}