# ssproxy

super simple proxy using Tornado

Features:
- http and https
- socks5
- shadowsocks client

# Install

    $pip install tornado
    $git clone https://github.com/liangsijian/ssproxy.git
    $cd ssproxy

# Usage

Options:

    $python proxy.py --help

    proxy.py options:

      --port                           socks listen port (default 3333)
      --proxy=shadow|http|socks5       proxy method (default shadow)
      --shadow                         shadow server address
      --shadow-method                  shadow crypto method (default aes-256-cfb)
      --shadow-password                shadow server password
      --shadow-port                    shadow server port
      --version                        show version information

run as a http proxy:

    $python proxy.py --method=http --port=8080

run as a socks5 proxy:

    $python proxy.py --method=socks5 --port=1080

run as a shadowsocks client:

    $python proxy.py --shadow=<address> --shadow-port=<port> --shadow-password=<password>

# TODO
- dynamic config and running status using browser
- plugin support
- ssproxy server to cross `f*re-w*lls`
