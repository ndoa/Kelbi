# Boots MHO and overrides the server IP:Port, made by ndoA.
#
# Requires Frida, install with:
#   `py -3 -m pip install frida`
#
# Run in an administrator command prompt with:
#   `py -3 mho_boot.py MHOClient.exe`

import frida
import sys


def main():
    # Attach to the process
    pID = frida.spawn(
        [r"C:\Program Files\TencentGame\Monster Hunter Online\Bin\Client\Bin32\MHOClient.exe", r"-qos_id=food -q -loginqq=1234567890123456789"])
    session = frida.attach(pID)

    # Create our JS injected script:
    script = session.create_script("""
    let serverUrl = "127.0.0.1:8142"
    let modName = "CryGame.dll";
    let cryGameMod;
    const addr_start_do_connect_svr = ptr(0x457800);

    waitForModuleToLoad();
    function waitForModuleToLoad(){
        try{
            cryGameMod = Process.getModuleByName(modName);
        }
        catch(err) {
            //console.log("Waiting for " + modName);
            setTimeout(waitForModuleToLoad, 20);
            return;
        }

        console.log("Got " + modName);
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

                // Strings allocated with allocUtf8String will only live until V8 garbage collects
                // the JS objects. To prevent this from being garbage collected, we attach it to
                // the hook object which is attached to the lifetime of the current thread: 
                this._url_lifetime_holder = newUrlPtr;
            }
        });
    }

    """)

    script.load()

    frida.resume(pID)
    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()


if __name__ == '__main__':
    main()
