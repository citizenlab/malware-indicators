import "pe"

/*
*
* This section of the rules are all specific to the new 2016
* KeyBoy sample targeting the Tibetan community. Other following
* sections capture file characteristics observed across multiple
* years of development. Don't miss the exploit doc signatures
* at the very end.
*
*/
rule new_keyboy_export
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the new 2016 sample's export"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        //The malware family seems to share many exports
        //but this is the new kid on the block.
        pe.exports("cfsUpdate")
}


rule new_keyboy_header_codes
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the 2016 sample's header codes"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        $s1 = "*l*" wide fullword
        $s2 = "*a*" wide fullword
        $s3 = "*s*" wide fullword
        $s4 = "*d*" wide fullword
        $s5 = "*f*" wide fullword
        $s6 = "*g*" wide fullword
        $s7 = "*h*" wide fullword

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        all of them
}


/*
*
* This section of the rules are all broader and will hit on
* older KeyBoy samples and other samples possibly part of a
* a larger development effort.
*
*/

rule keyboy_commands
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the 2016 sample's sent and received commands"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        $s1 = "Update" wide fullword
        $s2 = "UpdateAndRun" wide fullword
        $s3 = "Refresh" wide fullword
        $s4 = "OnLine" wide fullword
        $s5 = "Disconnect" wide fullword
        $s6 = "Pw_Error" wide fullword
        $s7 = "Pw_OK" wide fullword
        $s8 = "Sysinfo" wide fullword
        $s9 = "Download" wide fullword
        $s10 = "UploadFileOk" wide fullword
        $s11 = "RemoteRun" wide fullword
        $s12 = "FileManager" wide fullword

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        6 of them
}

rule keyboy_errors
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the sample's shell error2 log statements"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        //These strings are in ASCII pre-2015 and UNICODE in 2016
        $error = "Error2" ascii wide
        //2016 specific:
        $s1 = "Can't find [%s]!Check the file name and try again!" ascii wide
        $s2 = "Open [%s] error! %d" ascii wide
        $s3 = "The Size of [%s] is zero!" ascii wide
        $s4 = "CreateThread DownloadFile[%s] Error!" ascii wide
        $s5 = "UploadFile [%s] Error:Connect Server Failed!" ascii wide
        $s6 = "Receive [%s] Error(Recved[%d] != Send[%d])!" ascii wide
        $s7 = "Receive [%s] ok! Use %2.2f seconds, Average speed %2.2f k/s" ascii wide
        $s8 = "CreateThread UploadFile[%s] Error!" ascii wide
        //Pre-2016:
        $s9 = "Ready Download [%s] ok!" ascii wide
        $s10 = "Get ControlInfo from FileClient error!" ascii wide
        $s11 = "FileClient has a error!" ascii wide
        $s12 = "VirtualAlloc SendBuff Error(%d)" ascii wide
        $s13 = "ReadFile [%s] Error(%d)..." ascii wide
        $s14 = "ReadFile [%s] Data[Readed(%d) != FileSize(%d)] Error..." ascii wide
        $s15 = "CreateThread DownloadFile[%s] Error!" ascii wide
        $s16 = "RecvData MyRecv_Info Size Error!" ascii wide
        $s17 = "RecvData MyRecv_Info Tag Error!" ascii wide
        $s18 = "SendData szControlInfo_1 Error!" ascii wide
        $s19 = "SendData szControlInfo_3 Error!" ascii wide
        $s20 = "VirtualAlloc RecvBuff Error(%d)" ascii wide
        $s21 = "RecvData Error!" ascii wide
        $s22 = "WriteFile [%s} Error(%d)..." ascii wide

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        $error and 3 of ($s*)
}


rule keyboy_systeminfo
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the system information format before sending to C2"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        //These strings are ASCII pre-2015 and UNICODE in 2016
        $s1 = "SystemVersion:    %s" ascii wide
        $s2 = "Product  ID:      %s" ascii wide
        $s3 = "InstallPath:      %s" ascii wide
        $s4 = "InstallTime:      %d-%d-%d, %02d:%02d:%02d" ascii wide
        $s5 = "ResgisterGroup:   %s" ascii wide
        $s6 = "RegisterUser:     %s" ascii wide
        $s7 = "ComputerName:     %s" ascii wide
        $s8 = "WindowsDirectory: %s" ascii wide
        $s9 = "System Directory: %s" ascii wide
        $s10 = "Number of Processors:       %d" ascii wide
        $s11 = "CPU[%d]:  %s: %sMHz" ascii wide
        $s12 = "RAM:         %dMB Total, %dMB Free." ascii wide
        $s13 = "DisplayMode: %d x %d, %dHz, %dbit" ascii wide
        $s14 = "Uptime:      %d Days %02u:%02u:%02u" ascii wide



    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        7 of them
}


rule keyboy_related_exports
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the new 2016 sample's export"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        //The malware family seems to share many exports
        //but this is the new kid on the block.
        pe.exports("Embedding") or
        pe.exports("SSSS") or
        pe.exports("GetUP")
}

// Note: The use of the .Init section has been observed in nearly
// all samples with the exception of the 2013 VN dropper from the
// Rapid7 blog. The config data was stored in that sample's .data
// section.
rule keyboy_init_config_section
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the Init section where the config is stored"
        date = "2016-08-28"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        //Payloads are normally smaller but the new dropper we spotted
        //is a bit larger.
        filesize < 300KB and


        //Observed virtual sizes of the .Init section vary but they've
        //always been 1024, 2048, or 4096 bytes.
        for any i in (0..pe.number_of_sections - 1):
            (
                pe.sections[i].name == ".Init" and
                pe.sections[i].virtual_size % 1024 == 0
            )
}


/*
*
* These signatures fire on the exploit documents used in this
* operation.
*
*/
rule CVE_2012_0158_KeyBoy {
  meta:
      author = "Etienne Maynier <etienne@citizenlab.ca>"
      description = "CVE-2012-0158 variant"
      file = "8307e444cad98b1b59568ad2eba5f201"


  strings:
      $a = "d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff09000600000000000000000000000100000001" nocase // OLE header
      $b = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" nocase // junk data
      $c = /5(\{\\b0\}|)[ ]*2006F00(\{\\b0\}|)[ ]*6F007(\{\\b0\}|)[ ]*400200045(\{\\b0\}|)[ ]*006(\{\\b0\}|)[ ]*E007(\{\\b0\}|)[ ]*400720079/ nocase
      $d = "MSComctlLib.ListViewCtrl.2"
      $e = "ac38c874503c307405347aaaebf2ac2c31ebf6e8e3" nocase //decoding shellcode


  condition:
      all of them
}
