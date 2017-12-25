# DHCP-Sniffer
This is a python based application to sniffer DHCP datagrams. What is the benefit when you use DHCP-Sniffer:
* List assinged IPv4 address from any device in local network
* List DHCP-option 55 of any device in local network for device identification (fingerprint)

Only support IPv4, and IPv6 not support yet...

# Requirements
* Python 3

# Usage
## Linux
1. Usage
   * <-i interface> : specify sniffer interface. default is eth0.
   * <-d> : show more detail captured packet information including source/dest IP, source/dest MAC, and DHCP option 12, 50, 53, 54, 55. All __DHCP broadcast__ are captured.
   ```bash
   $ python3 dhcp_sniffer.py -h
   usage: dhcp_sniffer.py [-h] [-i INTERFACE] [-d]

   optional arguments:
     -h, --help            show this help message and exit
     -i INTERFACE, --interface INTERFACE
                           sniffer interface to get DHCP packets. default is eth0
     -d, --detail          show more detail packet information. if not set, only
                           DHCPREQUEST show.
   ```
2. Display captured host name, MAC, ip address and DHCP-option 55. Only __DHCP Request__ is shown.
   ``` bash
   $ sudo pythone dhcp_sniffer.py [-i interface]
   Local Time                    Message Type        Host Name           MAC                 IPv4                Option 55
   ----------------------------------------------------------------------------------------------------------------------------------
   2017-12-25 16:36:39 +0800     DHCPREQUEST         Benson-MBP        e4:2c:56:xx:xx:xx   10.2.6.21           1,121,3,6,15,119,252,95,44,46
   2017-12-25 16:39:32 +0800     DHCPREQUEST         Benson-iPhone     b8:53:ac:xx:xx:xx   10.2.6.25           1,121,3,6,15,119,252
   ```

## Windows
The differences with Linux version are below:
* no __MAC__ is shown
* no argument __<-i interface>__
```bash
> python3.exe dhcp_sniffer_win.py
```
