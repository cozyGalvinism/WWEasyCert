# WWEasyCert

Tool for generating a chain certificate, as well as installing it to a WEBWARE server.

## Usage

```usage
Usage:
  WWEasyCert [options] cert privkey ca [intermediates ...]

Arguments:
  cert             Path to certificate file
  privkey          Path to private key file
  ca               Path to CA certificate file
  [intermediates ...]
                   Paths to one or more intermediate certificates

Options:
  -h, --help
  -p, --password=PASSWORD    Password for the private key
  -i, --install=INSTALL      Path to WWS for installing the certificate files
```
