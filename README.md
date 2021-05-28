# veilig

Toy tls certificate viewer that I built because openssl s_client confuses me

Source available at: https://github.com/noqqe/veilig/

Please report any issues at: https://github.com/noqqe/veilig/issues/

## Install

```
brew install noqqe/tap/veilig
```

or

```
brew tap noqqe/tap
brew install veilig
```

## Usage

Using host:port combination

```
veilig heise.de:443
veilig lobste.rs:443
```

Using url schema:

```
veilig https://openbsd.org
```

Using local files 

```
veilig /tmp/cert.pem
```

## License

Licensed under MIT license.

See [LICENSE.txt](https://raw.githubusercontent.com/noqqe/veilig/master/LICENSE.txt) file for details.
