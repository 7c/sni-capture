# SNI Capture
This package uses pcap package to listen on default interface and port 443 to determine all TLS HELO Handshakes and SNI Extention. You may need https://github.com/node-pcap/node_pcap for details, how to use `createSession` method inside the code. Out of the box, this tool will console log everything it can find.

## Purphose
imagine you have purchased a domainname and you do not know if this domain has traffic and if so you want to know if you receive https traffic and if so you need to know which subdomain you need to set-up. This small tool will help you seeing all SNI Extention handshakes of TLS.

## Requirements
`apt install build-essential libpcap-dev`