# schwatz

Schwatz is a simple broadcast chat.
The word 'Schwatz' means 'chat' in german.
The schwatz project contains 'schwatz', the chat client and 'schwatz-server', the server, every client is supposed to connect to.

## Features

- [x] plain TCP communication
- [x] encryption

You may also want to view the [issues tab](https://github.com/tim-tm/schwatz/issues) for more details.

## Getting started

### Building schwatz

Toolchain:
- any C compiler

Libraries:
- pthread
- [sodium](https://doc.libsodium.org/)

Compile schwatz:
```sh
cc -Wall -Wextra nob.c -o nob
./nob
```

### Using schwatz

Start by running the server:
```sh
./schwatz server 127.0.0.1
```

The default port is 9999, you can specify a custom port (e.g. `1337`) via. the command args:
```sh
./schwatz server 127.0.0.1 1337
```

Now connect to the server:
```sh
./schwatz client 127.0.0.1
```

The client also uses port `9999` by default, you can also specify a custom port:
```sh
./schwatz client 127.0.0.1 1337
```

## Documentation

If you're interested in the way schwatz is implemented, take a look at the [protocol.md](https://github.com/tim-tm/schwatz/blob/main/docs/protocol.md).

## Contributing

Contributions are welcomed, please take a look at the [TODO.md](https://github.com/tim-tm/schwatz/blob/main/TODO.md) file.
Everything should of course be compatible with the [license](https://github.com/tim-tm/schwatz/blob/main/LICENSE).
