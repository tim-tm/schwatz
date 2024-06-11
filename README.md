# schwatz

Schwatz is a simple broadcast chat.
The word 'Schwatz' means 'chat' in german.
The schwatz project contains 'schwatz', the chat client and 'schwatz-server', the server, every client is supposed to connect to.

## Features

- [x] plain TCP communication
- [ ] encryption

You may also want to view the [issues tab](https://github.com/tim-tm/schwatz/issues) for more details.

## Getting started

### Building schwatz

Toolchain:
- GNU Make
- GCC

Libraries:
- pthread
- [sodium](https://doc.libsodium.org/)

Clone the github repository:
```sh
https://github.com/tim-tm/schwatz.git
```

Compile schwatz and schwatz-server:
```sh
make
```

### Using schwatz

Start by running the server:
```sh
cd schwatz-server
make run
```

The default port is 9999, you can specify a custom port via. the command args:
```sh
cd schwatz-server/build
./schwatz-server <port>
```

Now connect to the server:
```sh
cd schwatz/build
./schwatz <hostname> <port>
```

Connecting on the default port would look like this:
```sh
./schwatz localhost 9999
```

## Contributing

Contributions are welcomed, please take a look at the [issue-tracker](https://github.com/tim-tm/schwatz/issues) or 
the [TODO.md](https://github.com/tim-tm/schwatz/blob/main/TODO.md) file.

Everything should of course be compatible with the [license](https://github.com/tim-tm/schwatz/blob/main/LICENSE).
