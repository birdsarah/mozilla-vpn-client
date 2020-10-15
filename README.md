# Mozilla VPN

See: https://vpn.mozilla.org

## Dependencies

MozillaVPN requires Qt5 (5.15 or higher)

## How to build from the source code

### Linux

On linux, the compilation of MozillaVPN is relative easy. You need the
following dependencies:

- Qt5 >= 5.15.0
- libpolkit-gobject-1-0 >=0.105
- wireguard >=1.0.20200513
- wireguard-tools >=1.0.20200513
- resolvconf >= 1.82

The procedure is the following:
1. Update the submodules:
  $ git submodule init
  $ git submodule update --remote
2. Compile:
  $ qmake PREFIX=/usr
  $ make -j4
3. Install:
  $ sudo make install
4. Run:
  $ mozillavpn

The installation phase is important because mozillavpn needs to talk with
mozillavpn-daemon (see the code in linux/daemon) via DBus.

### MacOS

On macOS, we strongly suggest to compile Qt5 statically. See: ./scripts/qt5\_compile.sh

The procedure to compile MozillaVPN for macOS is the following:

1. Install XCodeProj:
  $ [sudo] gem install xcodeproj
2. Update the submodules:
  $ git submodule init
  $ git submodule update --remote
3. Run the script (use QT\_MACOS\_BIN env to set the path for the Qt5 macos build bin folder):
  $ ./scripts/apple\_compile.sh macos
4. Open Xcode and run/test/archive/ship the app

### IOS

The IOS procedure is similar to the macOS one:
1. Install XCodeProj:
  $ [sudo] gem install xcodeproj
2. Update the submodules:
  $ git submodule init
  $ git submodule update --remote
3. Run the script (use QT\_IOS\_BIN env to set the path for the Qt5 ios build bin folder):
  $ ./scripts/apple\_compile.sh ios
4. Open Xcode and run/test/archive/ship the app

### Other platforms

We are working on Android and Windows.

## Bug report

Please file bugs here: https://github.com/mozilla-mobile/mozilla-vpn-client/issues
