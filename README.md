# Pwnamap Plugin

## Main Repo:
https://github.com/JAKAMI99/pwnamap

## Features
[x] Autoupload all new Handshakes, which will be listed in /handshakes in your pwnamap WebUI
[ ] Send information about Stats (Sessions, Epochs, seen Networks,...)
[ ] More soon™


## Install the plugin

ssh into your pwnagotchi

```
sudo su
cd /usr/local/share/pwnagotchi/custom-plugins/
wget https://raw.githubusercontent.com/JAKAMI99/pwnamap-plugin/main/pwnamap.py
nano /etc/pwnagotchi/config.toml
```
Append the following lines to your config
```
main.plugins.pwnamap.enabled = true
main.plugins.pwnamap.api_key = "" # Found in your pwnamap instance under /settings
main.plugins.pwnamap.api_url = "https://jakami.de" # Change this to your URL (Format: http://DOMAIN_or_IP)
main.plugins.pwnamap.api_port= "1337"   
```
Add your API key from the Settings of pwnamap
Edit the api_url to match your public facing pwnamap instance and the api_port. (80 for Plain HTTP, 443 for HTTPS/SSL)

Save and close:
```
Ctrl+S (Check for "Wrote * Lines" message at the bottom)
Ctrl+X
```