# Kelbi

### Running client against localhost
Requirements:
* Python 3
* Frida ( `py -3 -m pip install frida` )
* MHO client's `CryGame.dll` with CRC32: `2358E8A9`

1. Modify `/scripts/mho_boot.py` to use the correct path to the `MHOClient.exe` for your installation.
2. Open a TCP server on port `8142`
   - e.g. on WSL2 run `nc -l 8142`
3. Run the game via the script `py -3 mho_boot.py`