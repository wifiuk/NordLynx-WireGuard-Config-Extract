# NordLynx WireGuard Config Extraction Script
Simple bash script to extract the NordLynx Wireguard config information that is needed to use wireguard and nord outside of the NordVPN application.

## Prerequisites
* A working internet connection
* NordVPN Installed & username/password already added to the NordVPN application
* Wireguard Tools installed ` sudo apt install wireguard -y`
* SSD/HDD Space to save a text file

## Usage

* ` chmod +x NordLynxExtractKeys.sh `

* ` sudo ./NordLynxExtractKeys.sh [COUNTRY CODE HERE] `

* example ` sudo ./NordLynxExtractKeys.sh uk `

## What does it do?

This script will:
* Connect to NordVPN
* Set the NordVPN application to use NordLynx
* It will connect to a server.
* It will run `wg show` and `grep` for some info.

Once this is done, it will
* Dump the information to the screen
* Automatically disconnect from NordVPN
* Dump the information into a file into the same directory as the sript using the currently connected server name.

If you are using PfSense and Wireguard you can also follow this guide to help you set it up.


* https://www.redpacketsecurity.com/step-by-step-guide-on-setting-up-nordlynx-wireguard-vpn-in-pfsense/

## Screenshot

![Screenshot](ScreenshotNord.png)

