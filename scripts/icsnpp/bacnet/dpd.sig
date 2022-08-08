signature bacnet_dpd {
  ip-proto == udp
  payload /\x81[\x00-x0b]/
  enable "bacnet"
}