signature bacnet_dpd {
  ip-proto == udp
  src-port == 1024-65535
  dst-port == 1024-65535
  payload /\x81\x0a..\x01/
  enable "bacnet"
}