# mho logger made by ndoA.
#
# Requires Frida, install with:
#   `py -3 -m pip install frida`
#
# Run in an administrator command prompt with:
#   `py -3 frida_packet_log2.py MHOClient.exe`

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
        [r"C:\Program Files\TencentGame\Monster Hunter Online\Bin\Client\Bin32\MHOClient.exe", r"qos_id=food -q -loginqq=1234567890123456789"])
    session = frida.attach(pID)

    # Create our JS injected script:
    script = session.create_script("""
    /*
    function readIP(addr) {
        let a0 = addr.add(0).readU8();
        let a1 = addr.add(1).readU8();
        let a2 = addr.add(2).readU8();
        let a3 = addr.add(3).readU8();
        return (a0 + "." + a1 + "." + a2 + "." + a3);
    }

    let pGetHostByName = Module.findExportByName("ws2_32.dll", 'gethostbyname')
    Interceptor.attach(pGetHostByName, {
        onEnter: function (args) {
            let hostname = args[0].readCString();
            console.log("(ret:" + this.returnAddress.toString() + ") " + "ws2_32.dll!gethostbyname called:" + hostname);
        },
        onLeave: function (retval) {
            // typedef struct hostent {
            //   char  *h_name; // 0
            //   char  **h_aliases; // 4
            //   short h_addrtype; // 8
            //   short h_length; // 10
            //   char  **h_addr_list;  // 12
            // } HOSTENT, *PHOSTENT, *LPHOSTENT;

            let h_addr_list = retval.add(12).readPointer();
            for(let i = 0; i <= 16; i += 4) {
                let addr = h_addr_list.add(i).readPointer();
                if(addr.isNull()) {
                    break
                }
                console.log("\t" + readIP(addr));
            }
        }
    });

    let pConnect = Module.findExportByName("ws2_32.dll", 'connect')
    Interceptor.attach(pConnect, {
        onEnter: function (args) {
            console.log("(ret:" + this.returnAddress.toString() + ") " + "ws2_32.dll!connect called");
        },
        onLeave: function (retval) {
        }
    });
    */




    function get_call_logger(name, modBase) {
        let idaBase = ptr(0xa7a0000);
        return {
            onEnter: function (args) {
                console.log("(ret:" + this.returnAddress.toString() + ", IDA-ret:" + this.returnAddress.sub(modBase).add(idaBase).toString() + ") " + name + " called");
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
    const addr_select_rev_sub = ptr(0x83f50);

    waitForCryGameModule();
    function waitForCryGameModule(){
        try{
            cryGameMod = Process.getModuleByName(modName);
        }
        catch(err) {
            //console.log("Waiting for " + modName);
            setTimeout(waitForCryGameModule, 20);
            return;
        }

        console.log("Got " + modName);
        waitForCryGameModuleUnpack();
    }

    function waitForCryGameModuleUnpack() {
        if(cryGameMod.base.add(addr_start_do_connect_svr).readU8() != 0x55) {
            setTimeout(waitForCryGameModuleUnpack, 50);
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

                // Strings allocated with allocUtf8String will only live until V8 garbage collects
                // the JS objects. To prevent this from being garbage collected, we attach it to
                // the hook object which is attached to the lifetime of the current thread: 
                this._url_lifetime_holder = newUrlPtr;
            }
        });

        Interceptor.attach(cryGameMod.base.add(addr_CClientLogic_ConnectServer), get_call_logger("CClientLogic_ConnectServer", cryGameMod.base));


        Interceptor.attach(cryGameMod.base.add(ptr(0xd60116)), {
            onEnter: function (args) {
                console.log("(ret:" + this.returnAddress.toString() + ") " + "url getter thing called");
                console.log(this.context.eax.toString())
            },
            onLeave: function (retval) {
            }
        });

        /*
        Interceptor.attach(cryGameMod.base.add(ptr(0xd60116)), {
            onEnter: function (args) {
                console.log("(ret:" + this.returnAddress.toString() + ") " + "url getter thing called");
                console.log(this.context.eax.toString())
            },
            onLeave: function (retval) {
            }
        });
        */
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
