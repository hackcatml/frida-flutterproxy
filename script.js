/* Global variables */
var appId = null;

var BURP_PROXY_IP = null;
var BURP_PROXY_PORT = null;

var libflutter_base = null;

var PT_LOAD_rodata_p_memsz = null;
var PT_LOAD_text_p_vaddr = null;
var PT_LOAD_text_p_memsz = null;
var PT_GNU_RELRO_p_vaddr = null;
var PT_GNU_RELRO_p_memsz = null;

var ssl_client_string_pattern_found_addr = null;
var verify_cert_chain_func_addr = null;

var Socket_CreateConnect_string_pattern_found_addr = null;
var Socket_CreateConnect_func_addr = null;

var GetSockAddr_func_addr = null;
var sockaddr = null;
/* Global variables */

/* Util functions */
// Find application package name
function findAppId() {
    var pm = Java.use('android.app.ActivityThread').currentApplication();
    return pm.getApplicationContext().getPackageName();
}

// Convert hex to byte string
function convertHexToByteString(hexString) {
    // Remove the '0x' prefix
    let cleanHexString = hexString.startsWith('0x') ? hexString.slice(2) : hexString;

    // Split the string into pairs of two characters
    let byteArray = cleanHexString.match(/.{1,2}/g);

    // Reverse the order of the byte pairs
    byteArray.reverse();

    // Join the byte pairs with spaces
    let byteString = byteArray.join(' ');

    return byteString;
}

// Convert ip string (e.g, "192.168.0.12") to byte array
function convertIpToByteArray(ipString) {
    // Split the IP address into its components
    let octets = ipString.split('.');

    // Convert each octet to a hexadecimal number and then to a byte
    let byteArray = octets.map(octet => parseInt(octet, 10));

    return byteArray;
}

// Byte flip
function byteFlip(number) {
    // Extract the high and low bytes
    let highByte = (number >> 8) & 0xFF;
    let lowByte = number & 0xFF;

    // Swap the high and low bytes
    let flippedNumber = (lowByte << 8) | highByte;

    return flippedNumber;
}

// Memory scan
function scanMemory(scan_start_addr, scan_size, pattern, for_what) {
    Memory.scan(scan_start_addr, scan_size, pattern, {
        onMatch: function(address, size){
            if (for_what == "ssl_client") {
                ssl_client_string_pattern_found_addr = address;
                console.log(`[*] ssl_client string pattern found at: ${address}`);
            } 
            else if (for_what == "ssl_client_adrp_add") {
                var adrp, add;
                var disasm = Instruction.parse(address);
                if (disasm.mnemonic == "adrp") {
                    adrp = disasm.operands.find(op => op.type === 'imm')?.value;
                    
                    disasm = Instruction.parse(disasm.next);
                    if (disasm.mnemonic != "add") {
                        disasm = Instruction.parse(disasm.next);
                    }
                    add = disasm.operands.find(op => op.type === 'imm')?.value;

                    if (adrp != undefined && add != undefined && ptr(adrp).add(add).toString() == ssl_client_string_pattern_found_addr.toString()) {
                        console.log(`[*] Found adrp add address: ${address}`);
                        // As we trace back, disassemble to find the address of the function to bypass the verify cert chain
                        for (let off = 0;; off += 4) {
                            disasm = Instruction.parse(address.sub(off));
                            if (disasm.mnemonic == "sub") {
                                disasm = Instruction.parse(disasm.next);
                                if (disasm.mnemonic == "stp" || disasm.mnemonic == "str") {
                                    verify_cert_chain_func_addr = address.sub(off);
                                    console.log(`[*] Found verify_cert_chain function address: ${verify_cert_chain_func_addr}`);
                                    break;
                                }
                            } else {
                                continue;
                            }
                        }
                    }
                }
            } 
            else if (for_what == "Socket_CreateConnect") {
                Socket_CreateConnect_string_pattern_found_addr = address;
                console.log(`[*] Socket_CreateConnect string pattern found at: ${address}`);
            }
            else if (for_what == "Socket_CreateConnect_func_addr") {
                Socket_CreateConnect_func_addr = address.sub(0x10).readPointer();
                console.log(`[*] Found Socket_CreateConnect function address: ${Socket_CreateConnect_func_addr}`);
                /*
                    Socket_CreateConnect function looks like this.
                    SUB             SP, SP, #0xD0
                    STR             X30, [SP,#0xD0+var_30]
                    STP             X22, X21, [SP,#0xD0+var_20]
                    STP             X20, X19, [SP,#0xD0+var_10]
                    MOV             W1, #1
                    MOV             X19, X0
                    BL              sub_89E20C
                    ADD             X1, SP, #0xD0+var_B0
                    BL              loc_67C15C   <---------------- branch to GetSockAddr function
                    MOV             W1, #2
                    MOV             X0, X19
                    BL              sub_89E20C
                */
                
                var bl_count = 0;
                for (let off = 0;; off += 4) {
                    let disasm = Instruction.parse(Socket_CreateConnect_func_addr.add(off));
                    if (disasm.mnemonic == "bl") {
                        bl_count++;
                        if (bl_count == 2) {
                            GetSockAddr_func_addr = ptr(disasm.operands.find(op => op.type === 'imm')?.value);
                            console.log(`[*] Found GetSockAddr function address: ${GetSockAddr_func_addr}`);
                            break;
                        } else {
                            continue;
                        }
                    }
                }
            }
        }, 
        onComplete: function(){
            // Scan adrp add opcode on the .text section to find the function which has "ssl_client" string
            if (for_what == "ssl_client" && ssl_client_string_pattern_found_addr != null) {
                var adrp_add_pattern = "?9 ?? ?? ?0 29 ?? ?? 91";
                if (appId == "com.alibaba.intl.android.apps.poseidon") {
                    // alibaba.com adrp add pattern is different
                    adrp_add_pattern = "?9 ?? ?? ?0 ?? ?? ?? ?? 29 ?? ?? 91";
                }
                scanMemory(libflutter_base.add(PT_LOAD_text_p_vaddr), PT_LOAD_text_p_memsz, adrp_add_pattern, "ssl_client_adrp_add");
            } 
            // Scan "Socket_CreateConnect" string pattern found address on the .data.rel.ro section to find the address of "Socket_CreateConnect" function
            else if (for_what == "Socket_CreateConnect" && Socket_CreateConnect_string_pattern_found_addr != null) {
                var addr_to_find = convertHexToByteString(Socket_CreateConnect_string_pattern_found_addr.toString());
                scanMemory(libflutter_base.add(PT_GNU_RELRO_p_vaddr), PT_GNU_RELRO_p_memsz, addr_to_find, "Socket_CreateConnect_func_addr");
            }
            console.log("[*] scan memory done");
        }
    })
}
/* Util functions */

/* Some variables and functions for elf parsing */
var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_APPEND = 1024;
var O_LARGEFILE = 32768;
var O_CREAT = 64;
var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

var p_types = {
    "PT_NULL":		0,		/* Program header table entry unused */
    "PT_LOAD":		1,		/* Loadable program segment */
    "PT_DYNAMIC":	2,		/* Dynamic linking information */
    "PT_INTERP":	3,		/* Program interpreter */
    "PT_NOTE":		4,		/* Auxiliary information */
    "PT_SHLIB":	    5,		/* Reserved */
    "PT_PHDR":		6,		/* Entry for header table itself */
    "PT_TLS":		7,		/* Thread-local storage segment */
    "PT_NUM":		8,		/* Number of defined types */
    "PT_LOOS":		0x60000000,	/* Start of OS-specific */
    "PT_GNU_EH_FRAME":	0x6474e550,	/* GCC .eh_frame_hdr segment */
    "PT_GNU_STACK":	0x6474e551,	/* Indicates stack executability */
    "PT_GNU_RELRO":	0x6474e552,	/* Read-only after relocation */
    "PT_GNU_PROPERTY":	0x6474e553,	/* GNU property */
    "PT_LOSUNW":	0x6ffffffa,
    "PT_SUNWBSS":	0x6ffffffa,	/* Sun Specific segment */
    "PT_SUNWSTACK":	0x6ffffffb,	/* Stack segment */
    "PT_HISUNW":	0x6fffffff,
    "PT_HIOS":		0x6fffffff,	/* End of OS-specific */
    "PT_LOPROC":	0x70000000,	/* Start of processor-specific */
    "PT_HIPROC":	0x7fffffff,	/* End of processor-specific */
}

function getExportFunction(name, ret, args) {
    var funcPtr;
    funcPtr = Module.findExportByName(null, name);
    if (funcPtr === null) {
        console.log("cannot find " + name);
        return null;
    } else {
        var func = new NativeFunction(funcPtr, ret, args);
        if (typeof func === "undefined") {
            console.log("parse error " + name);
            return null;
        }
        return func;
    }
}

var open = getExportFunction("open", "int", ["pointer", "int", "int"])
var close = getExportFunction("close", "int", ["int"]);
var lseek = getExportFunction("lseek", "int", ["int", "int", "int"]);
var read = getExportFunction("read", "int", ["int", "pointer", "int"]);
/* Some variables and functions for elf parsing */

/* Parsing elf function */
function parseElf(base) {
    base = ptr(base);
    var module = Process.findModuleByAddress(base);
    var fd = null;
    if (module !== null) {
        fd = open(Memory.allocUtf8String(module.path), O_RDONLY, 0);
    }
    
    // Read elf header
    var magic = "464c457f"
    var elf_magic = base.readU32()
    if (parseInt(elf_magic).toString(16) != magic) {
        console.log("[!] Wrong magic...ignore")
    }

    var arch = Process.arch
    var is32bit = arch == "arm" ? 1 : 0 // 1:32 0:64

    var size_of_Elf32_Ehdr = 0x34;
    var off_of_Elf32_Ehdr_shoff = 32;
    var off_of_Elf32_Ehdr_phentsize = 42;
    var off_of_Elf32_Ehdr_phnum = 44;
    var off_of_Elf32_Ehdr_shentsize = 46;
    var off_of_Elf32_Ehdr_shnum = 48;
    var off_of_Elf32_Ehdr_shstrndx = 50;

    var size_of_Elf64_Ehdr = 0x40;
    var off_of_Elf64_Ehdr_shoff = 40;
    var off_of_Elf64_Ehdr_phentsize = 54;
    var off_of_Elf64_Ehdr_phnum = 56;
    var off_of_Elf64_Ehdr_shentsize = 58;
    var off_of_Elf64_Ehdr_shnum = 60;
    var off_of_Elf64_Ehdr_shstrndx = 62;

    // Parse Ehdr(Elf header)
    var ehdrs_from_file = null;
    var phoff = is32bit ? size_of_Elf32_Ehdr : size_of_Elf64_Ehdr   // Program header table file offset
    var shoff = is32bit ? base.add(off_of_Elf32_Ehdr_shoff).readU32() : base.add(off_of_Elf64_Ehdr_shoff).readU64();   // Section header table file offset
    if (shoff == 0 && fd != null && fd !== -1) {
        console.log("[!] shoff is 0. Try to get it from the file")
        ehdrs_from_file = Memory.alloc(64);
        lseek(fd, 0, SEEK_SET);
        read(fd, ehdrs_from_file, 64);
        shoff = is32bit ? ehdrs_from_file.add(off_of_Elf32_Ehdr_shoff).readU32() : ehdrs_from_file.add(off_of_Elf64_Ehdr_shoff).readU64();
        console.log(`[*] shoff from the file: ${shoff}`)
    }
    var phentsize = is32bit ? base.add(off_of_Elf32_Ehdr_phentsize).readU16() : base.add(off_of_Elf64_Ehdr_phentsize).readU16();    // Size of entries in the program header table
    if (is32bit && phentsize != 32) {  // 0x20
        console.log("[!] Wrong e_phentsize. Should be 32. Let's assume it's 32");
        phentsize = 32;
    } else if (!is32bit && phentsize != 56) {
        console.log("[!] Wrong e_phentsize. Should be 56. Let's assume it's 56");
        phentsize = 56;
    }
    var phnum = is32bit ? base.add(off_of_Elf32_Ehdr_phnum).readU16() : base.add(off_of_Elf64_Ehdr_phnum).readU16();    // Number of entries in program header table
    // If phnum is 0, try to get it from the file
    if (phnum == 0) {
        if (fd != null && fd !== -1){
            console.log("[!] phnum is 0. Try to get it from the file")
            ehdrs_from_file = Memory.alloc(64);
            lseek(fd, 0, SEEK_SET);
            read(fd, ehdrs_from_file, 64);
            phnum = is32bit ? ehdrs_from_file.add(off_of_Elf32_Ehdr_phnum).readU16() : ehdrs_from_file.add(off_of_Elf64_Ehdr_phnum).readU16();
            if (phnum == 0) {
                console.log("[!] phnum is still 0. Let's assume it's 10. because we just need to find .dynamic section");
                phnum = 10;
            } else {
                console.log(`[*] phnum from the file: ${phnum}`)
            }
        } else {
            console.log("[!] phnum is 0. Let's assume it's 10. because we just need to find .dynamic section")
            phnum = 10;
        }
    }

    var shentsize = is32bit ? base.add(off_of_Elf32_Ehdr_shentsize).readU16() : base.add(off_of_Elf64_Ehdr_shentsize).readU16();    // Size of the section header
    if (is32bit && shentsize != 40) {  // 0x28
        console.log("[!] Wrong e_shentsize. Let's assume it's 40");
        shentsize = 40;
    } else if (!is32bit && shentsize != 64) {
        console.log("[!] Wrong e_shentsize. Let's assume it's 64");
        shentsize = 64;
    }
    var shnum = is32bit ? base.add(off_of_Elf32_Ehdr_shnum).readU16() : base.add(off_of_Elf64_Ehdr_shnum).readU16();    // Number of entries in section header table
    var shstrndx = is32bit ? base.add(off_of_Elf32_Ehdr_shstrndx).readU16() : base.add(off_of_Elf64_Ehdr_shstrndx).readU16();  // Section header table index of the entry associated with the section name string table
    if (shnum == 0 && fd != null && fd !== -1) {
        console.log("[!] shnum is 0. Try to get it from the file");
        ehdrs_from_file = Memory.alloc(64);
        lseek(fd, 0, SEEK_SET);
        read(fd, ehdrs_from_file, 64);
        shnum = is32bit ? ehdrs_from_file.add(off_of_Elf32_Ehdr_shnum).readU16() : ehdrs_from_file.add(off_of_Elf64_Ehdr_shnum).readU16();
        shstrndx = is32bit ? ehdrs_from_file.add(off_of_Elf32_Ehdr_shstrndx).readU16() : ehdrs_from_file.add(off_of_Elf64_Ehdr_shstrndx).readU16();
        console.log(`[*] shnum from the file: ${shnum}, shstrndx from the file: ${shstrndx}`)
    }
    // console.log(`phoff: ${phoff}, shoff: ${shoff}, phentsize: ${phentsize}, phnum: ${phnum}, shentsize: ${shentsize}, shnum: ${shnum}, shstrndx: ${shstrndx}`)

    // Parse Phdr(Program header)
    var phdrs = base.add(phoff)
    for (var i = 0; i < phnum; i++) {
        var phdr = phdrs.add(i * phentsize);
        var p_type = phdr.readU32();

        // if p_type is 0 check if it's really 0 from the file
        var phdrs_from_file = null;
        if (p_type === 0 && fd != null && fd !== -1) {
            phdrs_from_file = Memory.alloc(phnum * phentsize);
            lseek(fd, phoff, SEEK_SET);
            read(fd, phdrs_from_file, phnum * phentsize);
            p_type = phdrs_from_file.add(i * phentsize).readU32();
        }
        var p_type_sym = null;

        // check if p_type matches the defined p_type
        var p_type_exists = false;
        for (let key in p_types) {
            if (p_types[key] === p_type) {
                p_type_exists = true;
                p_type_sym = key;
                break;
            }
        }
        if (!p_type_exists) break;

        var p_offset = is32bit ? phdr.add(0x4).readU32() : phdr.add(0x8).readU64();
        var p_vaddr = is32bit ? phdr.add(0x8).readU32() : phdr.add(0x10).readU64();
        var p_paddr = is32bit ? phdr.add(0xc).readU32() : phdr.add(0x18).readU64();
        var p_filesz = is32bit ? phdr.add(0x10).readU32() : phdr.add(0x20).readU64();
        var p_memsz = is32bit ? phdr.add(0x14).readU32() : phdr.add(0x28).readU64();
        var p_flags = is32bit ? phdr.add(0x18).readU32() : phdr.add(0x4).readU32();
        var p_align = is32bit ? phdr.add(0x1c).readU32() : phdr.add(0x30).readU64();
        // console.log(`p_type: ${p_type}, p_offset: ${p_offset}, p_vaddr: ${p_vaddr}, p_paddr: ${p_paddr}, p_filesz: ${p_filesz}, p_memsz: ${p_memsz}, p_flags: ${p_flags}, p_align: {p_align}`);

        // if p_flags is 0, check it from the file
        if (p_flags === 0 && fd != null && fd !== -1) {
            phdrs_from_file = Memory.alloc(phnum * phentsize);
            lseek(fd, phoff, SEEK_SET);
            read(fd, phdrs_from_file, phnum * phentsize);
            var phdr_from_file = phdrs_from_file.add(i * phentsize);
            p_offset = is32bit ? phdr_from_file.add(0x4).readU32() : phdr_from_file.add(0x8).readU64();
            p_vaddr = is32bit ? phdr_from_file.add(0x8).readU32() : phdr_from_file.add(0x10).readU64();
            p_paddr = is32bit ? phdr_from_file.add(0xc).readU32() : phdr_from_file.add(0x18).readU64();
            p_filesz = is32bit ? phdr_from_file.add(0x10).readU32() : phdr_from_file.add(0x20).readU64();
            p_memsz = is32bit ? phdr_from_file.add(0x14).readU32() : phdr_from_file.add(0x28).readU64();
            p_flags = is32bit ? phdr_from_file.add(0x18).readU32() : phdr_from_file.add(0x4).readU32();
            p_align = is32bit ? phdr_from_file.add(0x1c).readU32() : phdr_from_file.add(0x30).readU64();
        }

        // .rodata section
        if (p_type_sym === 'PT_LOAD' && p_vaddr == 0) {
            PT_LOAD_rodata_p_memsz = p_memsz;
            continue;
        }

        // .text section
        if (p_type_sym === 'PT_LOAD' && p_vaddr != 0) {
            if (PT_LOAD_text_p_vaddr == null && PT_LOAD_text_p_memsz == null) {
                PT_LOAD_text_p_vaddr = p_vaddr;
                PT_LOAD_text_p_memsz = p_memsz;
            }
            continue;
        }

        if (p_type_sym === 'PT_GNU_RELRO') {
            PT_GNU_RELRO_p_vaddr = p_vaddr;
            PT_GNU_RELRO_p_memsz = p_memsz;
            break;
        }
    }
}
/* Parsing elf function */

/* Hook flutter engine function to capture the network traffic */
function hook(target) {
    if (target == "GetSockAddr") {
        // Hook SocketAddress::GetSockAddr function so we can get the address of sockaddr structure
        Interceptor.attach(GetSockAddr_func_addr, {
            onEnter: function(args) { 
                // console.log(`[!] sockaddr: ${args[1]}`);
                sockaddr = args[1];
            },
            onLeave: function(retval) {}
        })
        // Hook the socket function and replace the IP and port with our burp ones.
        Interceptor.attach(Module.findExportByName(null, "socket"), {
            onEnter: function(args) {
                if ((sockaddr != null && ptr(sockaddr).readU16() == 2) || sockaddr != null && ptr(sockaddr).readU16() == 10) {
                    console.log(`[*] Overwrite sockaddr as our burp proxy ip and port --> ${BURP_PROXY_IP}:${BURP_PROXY_PORT}`);
                    ptr(sockaddr).add(0x2).writeU16(byteFlip(BURP_PROXY_PORT));
                    ptr(sockaddr).add(0x4).writeByteArray(convertIpToByteArray(BURP_PROXY_IP));
                }
            },
            onLeave: function(retval) {}
        })
    }
    else if (target == "verifyCertChain") {
        // Hook the verify_cert_chain function and replace the return value with true, so we can capture ssl traffic
        Interceptor.attach(verify_cert_chain_func_addr, {
            onEnter: function(args) {},
            onLeave: function(retval) {
                if (retval == "0x0") {
                    console.log(`[*] verify cert bypass`);
                    var newretval = ptr(0x1);
                    retval.replace(newretval);
                }
            }
        })
    }
}
/* Hook flutter engine function to capture the network traffic */

/* main */
var awaitForCondition = function(callback) {
    var module_loaded = 0;
    var base = null;
    var int = setInterval(function() {
        Process.enumerateModulesSync()
        .filter(function(m){ return m['path'].toLowerCase().indexOf('libflutter.so') != -1; })
        .forEach(function(m) {
            console.log("[*] libflutter.so loaded!");
            base = Module.findBaseAddress('libflutter.so');
            return module_loaded = 1;
        })
        if(module_loaded) {
            clearInterval(int);
            callback(+base);
            return;
        }
    }, 0);
}

function init(base) {
    libflutter_base = ptr(base);
    console.log(`[*] libflutter.so base: ${libflutter_base}`);
    appId = findAppId();
    console.log(`[*] package name: ${appId}`);
    parseElf(libflutter_base);
    if (PT_LOAD_rodata_p_memsz != null) {
        // "ssl_client" string scan from the libflutter base address to the right before the .text section
        var pattern = '73 73 6C 5F 63 6C 69 65 6E 74 00';
        scanMemory(libflutter_base, PT_LOAD_rodata_p_memsz, pattern, "ssl_client");
        
        // "Socket_CreateConnect" string scan
        pattern = '53 6f 63 6b 65 74 5f 43 72 65 61 74 65 43 6f 6e 6e 65 63 74 00';
        scanMemory(libflutter_base, PT_LOAD_rodata_p_memsz, pattern, "Socket_CreateConnect");
    }

    var int_getSockAddr = setInterval(() => {
        if (GetSockAddr_func_addr != null) {
            console.log("[*] Hook GetSockAddr function");
            hook("GetSockAddr");
            clearInterval(int_getSockAddr);
        }
    }, 0);
    
    var int_verifyCertBypass = setInterval(() => {
        if (verify_cert_chain_func_addr != null) {
            console.log("[*] Hook verify_cert_chain function");
            hook("verifyCertChain");
            clearInterval(int_verifyCertBypass);
        }
    }, 0);
}

BURP_PROXY_IP = "192.168.0.76";
BURP_PROXY_PORT = 8083;

awaitForCondition(init);
/* main */
