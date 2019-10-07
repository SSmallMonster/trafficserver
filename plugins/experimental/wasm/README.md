Name
======

wasm - Embed the Power of WebAssembly into TrafficServer.


## Plugin Depedencies

### WAVM

```bash
git clone git@github.com:WAVM/WAVM.git
cd WAVM
git co nightly/2019-09-24 -b wasm
patch < $(THIS_DIR)/WAVM.patch
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

## Testing

Configure plugin

```
To /usr/local/etc/trafficserver/plugin.config add (substituting the location of this directory):

/home/yourname/trafficserver/plugins/experimental/wasm/.libs/wasm.so /home/yourname/trafficserver/plugins/experimental/wasm/example/http/http.wasm
```


Run ATS

```bash
sudo src/traffic_server/traffic_server
```

Run JTEST

```bash
tools/jtest/jtest -c1 -e1 -X
```
