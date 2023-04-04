# Kelbi
Work-in-progress project for MHO.

## Repo folder structure

* `/client_util` -> Client-side utilities and scripts
* `/toy_python_server` -> Toy/prototype server for rapid prototyping. **This will be replaced.**
* `/metalib` -> Extracted TDR metalib xml definition files.

## Running client against toy python server
### Requirements:
* Python 3
* Frida ( `py -3 -m pip install frida` )
* MHO client version `2.0.11.860`
   * `MHOClient.exe` with CRC32: `D81BB99A`
   * `CryGame.dll` with CRC32: `2358E8A9`
   * `protocalhandler.dll` with CRC32: `513D8AC0`

### Usage
In a shell/terminal (on same host where the client will run, as script connections to localhost):
```bash
$ cd Kelbi/toy_python_server
$ py -3 main.py
```

In a separate (administrator/elevated) command prompt:
```bash
$ cd Kelbi/client_util
$ py -3 mho_boot.py
```
