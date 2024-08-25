# Netmap TCP MSS Rewriter

Netmap TCP MSS Rewriter is a program designed to rewrite the TCP MSS (Maximum Segment Size) of network packets in real-time. This program leverages the Netmap framework to achieve high-performance packet processing.

The program operates on both IPv4 and IPv6 TCP packets, modifying the TCP MSS option based on the specified MSS values. It also supports VLAN tagging, making it suitable for environments using VLANs.

## Features
 - Rewriting of TCP MSS options for both IPv4 and IPv6 packets.
 - Support for VLAN tagged frames (802.1Q, 802.1ad)

## Environment

 * FreeBSD (tested on FreeBSD/amd64 14.1-RELEASE-p3)

## Build

 * `make`

## Build Flags

 * `-DDEBUG`: Enable debug log.
 * `-DNO_VLAN`: Disable VLAN tag support.

## Usage

 * `usage: netmap_tcpmss <ifname> <ipv4_mss> <ipv6_mss>`
   * `<ifname>`: Name of the target network interface. (e.g., `em2`, `em2.100`, `gif0`)
   * `<ipv4_mss>`: TCP MSS value for IPv4 TCP packets(e.g., `1414`)
   * `<ipv6_mss>`: TCP MSS value for IPv6 TCP packets(e.g., `1394`)

 * You may need to disable HW offloading features since it's not compatible with Netmap for example: `ifconfig em0 -rxcsum -txcsum -lro -tso -rxcsum6 -txcsum6`
 * To handle VLAN tags in Netmap application, you need to disable vlan tag related offloading features for example: `ifconfig em0 -vlanhwcsum -vlanhwfilter -vlanhwtag`

## Note

 * This program must be run with administrative privileges.
 * Use caution when deploying in a production environment, as the program may affect traffic on the target network interface.

## Author

 * [Kazuki Shimizu(kazubu)](https://github.com/kazubu/)
