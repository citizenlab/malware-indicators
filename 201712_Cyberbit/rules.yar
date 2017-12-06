rule PSS_Agent {
    meta:
        description = "PSS Agent versions 4.x and 5.x"
        author = "Geoffrey Alexander <geoff@citizenlab.ca>"
        date = "2017-07-20"

    strings:
        $cmdproc = "CmdProc_" wide

        $u1 = "SS_Agent" ascii
        $u2 = "pss-agent" ascii
        $u3 = "DC615DA9-94B5-4477-9C33-3A393BC9E63F" ascii
        $u4 = { 06 1f 41 49 4d 48 50 4f 31 }

        $s1 = "util::Process::" ascii
        $s2 = "util::Resource::" ascii
        $s3 = "util::System::" ascii
        $s4 = "/M:{0FA12518-0120-0910-A43C-0DAA276D2EA4}" wide
        $s5 = "Command is not allowed due to potential detection threat: %1%." wide
        $s6 = "(%d) %.64s\\%.64s\\%.64s|%.64s|%.64s|%.64s|%.64s|%.64s|%.64s" wide
        $s7 = "Name: %s Due: %02d/%02d/%04d %02d:%02d:%02d, Length: %d seconds" wide
        $s8 = "Image will be taken on the next Skype call session." wide
        $s9 = "\\\\.\\pipe\\BrowseIPC" wide
        $s10 = "RES_BINARY" wide
        $s11 = "/{433a-bbaf439-12982d4a-9c27}" wide

    condition:
        uint16(0) == 0x5a4d and $cmdproc and 1 of ($u*) and 4 of ($s*)
}

rule PSS_Pipeserver {
    meta:
        description = "PSS Pipeserver versions 4.x and 5.x"
        author = "Geoffrey Alexander <geoff@citizenlab.ca>"
        data = "2017-07-20"

    strings:
        $u1 = "pss-agent" ascii
        $u2 = "PSS_Agent" ascii
        $u3 = "Agent path too long (>= MAX_PATH)" ascii
        $u4 = "Agent is not running, executing it now\\n" ascii
        $u5 = "Failed to create PssClock!" ascii

        $s1 = "LnkProxy" ascii
        $s2 = "CUSTOMER\\Agent" ascii
        $s3 = "BrowseIPC" ascii
        $s4 = "CustomerConfig is not initialized yet" ascii
        $s5 = "RES_BINARY" ascii
        $s6 = "ipc::security_access::" ascii
        $s7 = "util::Resource::" ascii
        $s8 = "util::System::" ascii
        $s9 = "AgentAdminGlobalEventName" wide
        $s10 = "AgentDummyKillGlobalEventName" wide
        $s11 = "AgentGlobalEventName" wide
        $s12 = "AgentKillGlobalEventName" wide
        $s13 = "AgentPipeServerInitGlobalEventName" wide
        $s14 = "AgentUninstallGlobalEventName" wide
        $s15 = "/M:{0FA12518-0120-0910-A43C-0DAA276D2EA4}" wide
        $s16 = "\\\\.\\pipe\\BrowseIPC" wide
        $s17 = "RES_BINARY" wide
        $s18 = "/{433a-bbaf439-12982d4a-9c27}" wide

    condition:
        uint16(0) == 0x5a4d and 1 of ($u*) and 8 of ($s*)
}

rule PSS_lnkproxy {
    meta:
        description = "PSS lnkproxy versions 4.x and 5.x"
        author = "Geoffrey Alexander <geoff@citizenlab.ca>"
        date = "2017-07-20"

    strings:
        $s1 = "COMMAND_LINE_BEGIN:" ascii
        $s2 = ":COMMAND_LINE_END:" ascii
        $s3 = "Could not execute process when no command is specified" ascii
        $s4 = "lnkproxy.db" ascii
        $s5 = "SPAWN_COMMAND_BEGIN:" ascii
        $s6 = ":SPAWN_COMMAND_END" ascii
        $s7 = "util::Deserializer::" ascii
        $s8 = "util::FileDeserializer::" ascii
        $s9 = "util::File::" ascii
        $s10 = "util::Process::" ascii
        $s11 = "util::System::" ascii

    condition:
        uint16(0) == 0x5a4d and 4 of ($s*)
}

rule PSS_Agent_v6 {
    meta:
        description = "PSS Agent version 6.0.0 and 6.1.0"
        author = "Geoffrey Alexander <geoff@citizenlab.ca>"
        date = "2017-07-20"

    strings:
        $cmdproc = "CmdProc_" wide

        $u1 = "C:\\Windows\\temp\\KB2979214.pdb" ascii
        $u2 = { 06 1f 41 49 4d 48 50 4f 31 }

        $s1 = "Did not complete transaction with pipe server" wide
        $s2 = "SkypeControlAPIAttach" wide
        $s3 = "SkypeControlAPIDiscover" wide
        $s4 = "URL###Execute" wide
        $s5 = "Failed to AddClipboardFormatListener, error [" ascii
        $s6 = "transactionrequest.<xmlattr>" wide
        $s7 = "DC615DA9-94B5-4477-9C33-3A393BC9E63F" ascii
        $s8 = "getip.<xmlattr>.agentid" wide
        $s9 = "AVAgentInstallException@agent@@" ascii
        $s10 = "AVAgentCommandsException@agent@@" ascii
        $s11 = "AVAgentCustomerConfigException@agent@@" ascii
        $s12 = "AVTransactionParsingException@communication@@agent" ascii
        $s13 = "AVStorageException@config@agent@@" ascii
        $s14 = "AVDBStorageException@db@agent@@" ascii

        $str_decrypt_loop = { 8b 47 04 8b ce 83 e1 03 c1 e1 03 ba ?? ?? ?? ?? d3 ea 32 54 35 ?? 88 14 06 46 3b f3 }

    condition:
        uint16(0) == 0x5a4d and $cmdproc and $str_decrypt_loop and 1 of ($u*) and 8 of ($s*)
}

rule PSS_lnkproxy_v6 {
    meta:
        description = "PSS lnkproxy version 6.0.0 and 6.1.0"
        author = "Geoffrey Alexander <geoff@citizenlab.ca>"
        date = "2017-07-20"

    strings:
        $s1 = "C:\\Windows\\temp\\KB2971112.pdb"
        $s2 = "AVResourceException@exception@util@@" ascii
        $s3 = "AVLnkControllerException@LnkProxy@@" ascii
        $s4 = "AVLnkPayloadException@@" ascii
        $s5 = "AVShellLinkException@LnkProxy@@" ascii
        $s6 = "AVFileUtilitiesException@LnkProxy@@" ascii
        $s7 = "AVLnkEntryException@LnkProxy@@" ascii
        $s8 = "AVFileRollbackException@LnkProxy@@" ascii

        $str_decrypt_loop = { 8b 47 04 8b ce 83 e1 03 c1 e1 03 ba ?? ?? ?? ?? d3 ea 32 54 35 ?? 88 14 06 46 3b f3 }

    condition:
        uint16(0) == 0x5a4d and 3 of ($s*) and $str_decrypt_loop
}

rule PSS_Pipeserver_v6 {
    meta:
        description = "PSS Pipeserver version 6.0.0 and 6.1.0"
        author = "Geoffrey Alexander <geoff@citizenlab.ca>"
        date = "2017-07-20"

    strings:
        $p1 = "PSS_Agent" ascii
        $p2 = "pss-agent" ascii

        $s1 = "%2s%u.%u.%u.%u\\\\n" wide
        $s2 = "CustomerConfigException@agent" ascii

        $str_decrypt_loop = { 8b 47 04 8b ce 83 e1 03 c1 e1 03 ba ?? ?? ?? ?? d3 ea 32 54 35 ?? 88 14 06 46 3b f3 }

    condition:
        uint16(0) == 0x5a4d and $str_decrypt_loop and 1 of ($p*) and 1 of ($s*)
}
