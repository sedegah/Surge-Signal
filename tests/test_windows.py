from __future__ import annotations

from surge_signal.wireless.windows_wifi import parse_interfaces, parse_networks, parse_drivers


NETWORKS = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : LabNetwork
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:11:22:33
         Signal             : 82%
         Radio type         : 802.11ac
         Band               : 5 GHz
         Channel            : 36

SSID 2 :
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 00:1e:a6:ee:a6:00
         Signal             : 40%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6
"""

INTERFACES = """
    Name                   : Wi-Fi
    Description            : Realtek 8822CE Wireless LAN 802.11ac PCI-E NIC
    GUID                   : 1e1c74b9-2310-4ad5-90d5-bfc306ffe1ca
    Physical address       : 80:30:49:a5:15:1d
    State                  : connected
    SSID                   : LabNetwork
    AP BSSID               : aa:bb:cc:11:22:33
    Band                   : 5 GHz
    Channel                : 36
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Signal                 : 82%
    Receive rate (Mbps)    : 866
    Transmit rate (Mbps)   : 866
"""


def test_parse_netsh_networks() -> None:
    networks = parse_networks(NETWORKS)
    assert len(networks) == 2
    lab = next(item for item in networks if item.ssid == "LabNetwork")
    assert lab.bssid == "AA:BB:CC:11:22:33"
    assert lab.channel == 36
    assert lab.band == "5 GHz"
    assert lab.signal_dbm == -59
    assert lab.authentication == "WPA2-Personal"
    hidden = next(item for item in networks if item.bssid == "00:1E:A6:EE:A6:00")
    assert hidden.hidden
    assert hidden.family.value == "open"


def test_parse_interfaces_bssid_and_rates() -> None:
    interfaces = parse_interfaces(INTERFACES)
    assert len(interfaces) == 1
    interface = interfaces[0]
    assert interface.bssid == "AA:BB:CC:11:22:33"
    assert interface.channel == 36
    assert interface.receive_rate == "866"
    assert interface.connected


def test_parse_drivers() -> None:
    output = """
    Interface name: Wi-Fi
    Driver                    : rtwlanu.sys
    Vendor                    : Realtek Semiconductor Corp.
    Provider                  : Realtek Semiconductor Corp.
    Date                      : 12/08/2022
    Version                   : 2024.0.4.108
    Radio types supported     : 802.11b 802.11g 802.11n 802.11a 802.11ac
    Authentication and cipher supported in infrastructure mode:
                                Open            None
                                WPA2-Personal   CCMP
    802.11w Management Frame Protection supported : Yes
    """
    parsed = parse_drivers(output)
    driver = parsed["wireless_driver"]
    assert driver["driver"] == "rtwlanu.sys"
    assert "802.11ac" in driver["radio_types"]
    assert driver["pmf_supported"] == "Yes"

