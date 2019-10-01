Name
======

wasm - Embed the Power of WebAssembly into TrafficServer.


## Plugin Depedencies

### WAVM

```bash
git clone git@github.com:WAVM/WAVM.git
cd WAVM
git co nightly/2019-09-24 -b wasm
cmake "."
make -j
sudo make install
sudo ldconfig
```

It is possible that later versions will work, but nightly/2019-09-24 is known to work.

## Plugin Development Dependencies

### emscripten

```bash
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk update-tags
./emsdk install 1.38.46
./emsdk activate 1.38.46

source ./emsdk\_env.sh
```

It is possible later versions will work, e.g.

```bash
./emsdk update-tags
./emsdk install latest
./emsdk activate latest
```

However 1.38.46 is known to work.

