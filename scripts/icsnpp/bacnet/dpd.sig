signature bacnet_dpd {
  ip-proto == udp
  src-port >= 1024
  dst-port >= 1024
  payload /\x81[\x0a\x0b]..\x01/
  enable "bacnet"
}