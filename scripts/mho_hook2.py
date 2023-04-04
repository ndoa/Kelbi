# mho logger made by ndoA.
#
# Requires Frida, install with:
#   `py -3 -m pip install frida`
#
# Run in an administrator command prompt with:
#   `py -3 mho_hook2.py MHOClient.exe`

import frida
import sys
import struct
import binascii


def on_message(message, data):
    print("[%s] => %s" % (message, data))


def main():
    # Attach to the process
    # -q 946282264 -src=tgp -game_id 45 -area 1 -zone_id 16909332
    pID = frida.spawn(
        [r"D:\mho\TencentGame\Monster Hunter Online\Bin\Client\Bin32\MHOClient.exe", r"qos_id=food -q -loginqq=1234567890123456789 -nosplash"])
    session = frida.attach(pID)

    # Create our JS injected script:
    script = session.create_script("""

    function get_call_logger(name, base) {
        return {
            onEnter: function (args) {
                console.log("(ret:" + this.returnAddress.toString() + ", RVA: base+" + this.returnAddress.sub(base).toString() + ") " + name + " called");
            }
        };
    }

    
    let serverUrl = "127.0.0.1:8142"
    let cryGameModName = "CryGame.dll";
    let cryGameMod;
    const addr_start_do_connect_svr = ptr(0x457800); //ptr(0xABF7800); 
    const addr_CClientLogic_ConnectServer = ptr(0x11a8bd0);

    let protocalHandlerModName = "ProtocalHandler.dll";
    let protocalHandlerMod;
    const addr_select_rev_sub = ptr(0x83620);

    Interceptor.attach(Module.findExportByName("ws2_32.dll", 'send'), get_call_logger("ws2_32.dll!send", Process.getModuleByName("ws2_32.dll").base));
    Interceptor.attach(Module.findExportByName("ws2_32.dll", 'recv'), get_call_logger("ws2_32.dll!recv", Process.getModuleByName("ws2_32.dll").base));
    Interceptor.attach(Module.findExportByName("ws2_32.dll", 'sendto'), get_call_logger("ws2_32.dll!sendto", Process.getModuleByName("ws2_32.dll").base));
    Interceptor.attach(Module.findExportByName("ws2_32.dll", 'recvfrom'), get_call_logger("ws2_32.dll!recvfrom", Process.getModuleByName("ws2_32.dll").base));

    console.log("waiting for crygame.dll and protocalhandler.dll");
    setTimeout(waitForCryGameDLL, 20);
    setTimeout(waitForProtocalHandlerDLL, 20);
    
    function waitForProtocalHandlerDLL() {
        // Retry until we get the module.
        try{
            protocalHandlerMod = Process.getModuleByName(protocalHandlerModName);
        }
        catch(err) {
            setTimeout(waitForProtocalHandlerDLL, 20);
            return;
        }
        console.log("Got " + protocalHandlerModName);


        // Wait for unpack.
        if(protocalHandlerMod.base.add(addr_select_rev_sub).readU8() != 0x8B) {
            setTimeout(waitForProtocalHandlerDLL, 50);
            return;
        }
        console.log("Module is now unpacked: " + protocalHandlerModName);


        Interceptor.attach(protocalHandlerMod.base.add(addr_select_rev_sub), get_call_logger("addr_select_rev_sub", protocalHandlerMod.base));
        Interceptor.attach(protocalHandlerMod.base.add(ptr(0x83600)), get_call_logger("net_send", protocalHandlerMod.base));
        Interceptor.attach(protocalHandlerMod.base.add(ptr(0x83640)), get_call_logger("net_sendall", protocalHandlerMod.base));

        Interceptor.attach(protocalHandlerMod.base.add(ptr(0x73dc0)), {
            onEnter: function (args) {
                console.log("perform_tpdu_decryption called! apiHandle: " + args[0])
                //Thread.sleep(1000);

                // Disable encryption (TCONN_SEC_NONE = 0)
                let encryption_mode_addr = args[0].add(0x84);
                console.log("mode: " + encryption_mode_addr.readU32())
                encryption_mode_addr.writeU32(0)
                console.log("mode: " + encryption_mode_addr.readU32())

                
                // int __cdecl perform_tpdu_decryption(
                //    TQQApiHandle *apiHandle,
                //    char *inputBuffer,
                //    unsigned int inputBufferLength,
                //    void **outputBuffer,
                //    unsigned int *outputBufferLength,
                //    int is_TPDU_CMD_PLAIN,
                //    int allow_unencrypted_packets)
                console.log("args[0]: " + args[0]);
                console.log("args[1]: " + args[1]);
                console.log("args[2]: " + args[2]);
                console.log("args[3]: " + args[3]);
                console.log("args[4]: " + args[4]);
                console.log("args[5]: " + args[5]);
                console.log("args[6]: " + args[6]);
                console.log("args[7]: " + args[7]);

                args[5] = ptr(1);
                // args[6] = ptr(1);

            },
            onLeave: function (retval) {
                console.log("perform_tpdu_decryption retval:" + retval)
            }
        });

        Interceptor.attach(protocalHandlerMod.base.add(ptr(0x73bb0)), {
            onEnter: function (args) {
                console.log("perform_tpdu_encryption called! apiHandle: " + args[0])
                //Thread.sleep(1000);

                // Disable encryption (TCONN_SEC_NONE = 0)
                let encryption_mode_addr = args[0].add(0x84);
                console.log("mode: " + encryption_mode_addr.readU32())
                encryption_mode_addr.writeU32(0)
                console.log("mode: " + encryption_mode_addr.readU32())

                // int __cdecl TQQApiHandle__perform_tpdu_encryption(
                //     TQQApiHandle *apiHandle,
                //     void *inputBuffer,
                //     signed int inputBufferLength,
                //     void **outputBuffer,
                //     signed int *outputBufferLength,
                //     int allow_unencrypted
                // )
                console.log("args[0]: " + args[0]);
                console.log("args[1]: " + args[1]);
                console.log("args[2]: " + args[2]);
                console.log("args[3]: " + args[3]);
                console.log("args[4]: " + args[4]);
                console.log("args[5]: " + args[5]);
                console.log("args[6]: " + args[6]);
                console.log("args[7]: " + args[7]);

                args[5] = ptr(1);
                // args[6] = ptr(1);

            },
            onLeave: function (retval) {
                console.log("perform_tpdu_encryption retval:" + retval)
            }
        });


        Interceptor.attach(protocalHandlerMod.base.add(ptr(0x75590)), {
            onEnter: function (args) {
                console.log("tqqapi_extract_syninfo called!")
            },
            onLeave: function (retval) {
                console.log("tqqapi_extract_syninfo retval:" + retval)
            }
        });
        Interceptor.attach(protocalHandlerMod.base.add(ptr(0x42ec0)), {
            onEnter: function (args) {
                console.log("CTdrProtocalHandler::TqqapiExtractSyninfo called!")
            },
            onLeave: function (retval) {
                console.log("CTdrProtocalHandler::TqqapiExtractSyninfo retval:" + retval)
            }
        });
    }

    function waitForCryGameDLL(){
        try{
            cryGameMod = Process.getModuleByName(cryGameModName);
        }
        catch(err) {
            //console.log("Waiting for " + cryGameModName);
            setTimeout(waitForCryGameDLL, 20);
            return;
        }

        console.log("Got " + cryGameModName);
        waitForModuleUnpack();
    }

    function waitForModuleUnpack() {
        if(cryGameMod.base.add(addr_start_do_connect_svr).readU8() != 0x55) {
            setTimeout(waitForModuleUnpack, 50);
            return;
        }
        console.log("Module is now unpacked.");
        hookCryGame();
    }

    function hookCryGame() {
        Interceptor.attach(cryGameMod.base.add(addr_start_do_connect_svr), {
            onEnter: function (args) {
                let newUrlPtr = Memory.allocUtf8String(serverUrl);
                this.context.sp.add(4).writePointer(newUrlPtr);

                console.log("mode: " + this.context.sp.add(4+4+4+4).readU32())
                // Enable TDR mode:
                //this.context.sp.add(4+4+4+4).writeU32(3)
                console.log("mode: " + this.context.sp.add(4+4+4+4).readU32())

                // Strings allocated with allocUtf8String will only live until V8 garbage collects
                // the JS objects. To prevent this from being garbage collected, we attach it to
                // the hook object which is attached to the lifetime of the current thread: 
                this._url_lifetime_holder = newUrlPtr;
            }
        });

        Interceptor.attach(cryGameMod.base.add(addr_CClientLogic_ConnectServer), get_call_logger("CClientLogic_ConnectServer", cryGameMod.base));

        Interceptor.attach(cryGameMod.base.add(ptr(0x121A1B0)), get_call_logger("crygame.dll!report_analytics", cryGameMod.base));

        Interceptor.attach(cryGameMod.base.add(ptr(0x4a5b0)), get_call_logger("crygame.dll!socket_send", cryGameMod.base));
        Interceptor.attach(cryGameMod.base.add(ptr(0x49b90)), get_call_logger("crygame.dll!net_send", cryGameMod.base));
        Interceptor.attach(cryGameMod.base.add(ptr(0x4a730)), get_call_logger("crygame.dll!socket_sendall", cryGameMod.base));
        Interceptor.attach(cryGameMod.base.add(ptr(0x4A960)), get_call_logger("crygame.dll!socket_recv", cryGameMod.base));
        Interceptor.attach(cryGameMod.base.add(ptr(0x4AAF0)), get_call_logger("crygame.dll!socket_recvall", cryGameMod.base));

        Interceptor.attach(cryGameMod.base.add(ptr(0x4570f0)), get_call_logger("crygame.dll!CSPkg::deserialize", cryGameMod.base));
        Interceptor.attach(cryGameMod.base.add(ptr(0x4202a0)), get_call_logger("crygame.dll!CSPkgHead::deserialize", cryGameMod.base));
        Interceptor.attach(cryGameMod.base.add(ptr(0x42f6c0)), get_call_logger("crygame.dll!CSPkgBody::deserialize", cryGameMod.base));
        Interceptor.attach(cryGameMod.base.add(ptr(0x10c800)), get_call_logger("crygame.dll!TdrBuf::read_i16", cryGameMod.base));

        
    }

    """)

    script.on('message', on_message)
    script.load()

    frida.resume(pID)
    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()


if __name__ == '__main__':
    main()


# CryGame.dll+11A8D14 - FF 56 14              - call dword ptr [esi+14] ; call start_do_connect_svr
