---
search:
  exclude: true
---
___

Quick start for all of my Kali environments
**Oh-My-Zsh**
```Python
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
```
**Install Bins**
```bash
sudo apt update -y
sudo apt install feroxbuster -y
sudo apt install alacritty -y
sudo apt install rlwrap -y
cd /tmp && git clone https://github.com/Jacob-Ham/gbins.git && cd gbins && pip3 install -r requirements.txt --break-system-packages && sudo /usr/bin/chmod u+x gbins.py && /usr/bin/sudo /usr/bin/cp -p gbins.py /usr/bin/gbins

cd /tmp && git clone https://github.com/Jacob-Ham/auth.git && cd auth && sudo /usr/bin/chmod u+x auth.py && /usr/bin/sudo /usr/bin/cp -p auth.py /usr/bin/auth

sudo apt install dirsearch -y
sudo apt install tmux -y
sudo apt install syncthing -y
sudo apt install awscli -y
mkdir -p ~/tools/kerbrute
cd ~/tools/kerbrute
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
sudo ln -s /home/kali/tools/kerbrute/kerbrute_linux_amd64 /usr/local/bin/kerbrute
chmod +x /home/kali/tools/kerbrute/kerbrute_linux_amd64
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do sudo apt-get remove $pkg; done
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo apt update -y
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo apt install ltrace -y
sudo apt install strace -y
python3 -m pip install ldeep --break-system-packages
sudo apt install gdb -y
sudo apt install python3.12-venv -y
sudo apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
sudo apt install python3-argcomplete
register-python-argcomplete nxc >> ~/.bashrc
register-python-argcomplete nxc >> ~/.zshrc
```
**Codium**
```Python
wget -qO - https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/raw/master/pub.gpg \
    | gpg --dearmor \
    | sudo dd of=/usr/share/keyrings/vscodium-archive-keyring.gpg
    
echo 'deb [ signed-by=/usr/share/keyrings/vscodium-archive-keyring.gpg ] https://download.vscodium.com/debs vscodium main' \
    | sudo tee /etc/apt/sources.list.d/vscodium.list
sudo apt update && sudo apt install codium
```
**Postman**
```Python
firefox https://dl.pstmn.io/download/latest/linux_64
cd ~/Downloads
tar -xvzf postman-linux-x64.tar.gz
sudo mv Postman /opt
sudo ln -s /opt/Postman/Postman /usr/bin/postman
```
**Install pwndbg**
```Python
cd /tmp && git clone https://github.com/pwndbg/pwndbg && cd pwndbg && bash setup.sh
```
**Espanso Grab**
```Python
mkdir -p ~/opt && wget -O ~/opt/Espanso.AppImage 'https://github.com/federico-terzi/espanso/releases/download/v2.2.3/Espanso-X11.AppImage' && chmod u+x ~/opt/Espanso.AppImage && sudo ~/opt/Espanso.AppImage env-path register && espanso service register
```
**Espanso Configure**
```Python
rm ~/.config/espanso/match/base.yml && wget https://raw.githubusercontent.com/Jacob-Ham/kali-configs/main/espanso/base.yml -P ~/.config/espanso/match/ && espanso start
```
tmux config
```bash
tmux show -g | sed 's/^/set-option -g /' > ~/.tmux.conf
```

```bash
echo 'set -g history-limit 500000' >> ~/.tmux.conf
echo 'set -g mode-keys vi' >> ~/.tmux.conf
tmux source-file ~/.tmux.conf
```


**Install KDE and remove Kali-Desktop**
Install KDE
```C
sudo apt install kde-full -y
```
Remove kali desktop
```C
sudo apt autoremove kali-defaults kali-root-login desktop-base xfce4 xfce4-places-plugin xfce4-goodies -y
```
**Cloudtools**
```JavaScript
#!/usr/bin/env bash
# Get sudo credentials so that we can do privileged installations
username=$(id -u -n 1000)
arch=$(uname -m)
sudo -v
# Preparation tasks 
install_dir=/opt/mcrtp_bootcamp_tools
sudo mkdir -p "$install_dir"
sudo chown $username:$username $install_dir
sudo apt update && sudo apt install unzip curl hashcat evil-winrm pipx docker.io docker-compose -y
# Install Powershell tools
git clone https://github.com/Gerenios/AADInternals $install_dir/AADInternals
git clone https://github.com/dafthack/GraphRunner $install_dir/GraphRunner
git clone https://github.com/f-bader/TokenTacticsV2 $install_dir/TokenTacticsV2
git clone https://github.com/dafthack/MFASweep $install_dir/MFASweep
# Install python tools
git clone https://github.com/yuyudhn/AzSubEnum $install_dir/AzSubEnum
git clone https://github.com/joswr1ght/basicblobfinder $install_dir/basicblobfinder
git clone https://github.com/gremwell/o365enum $install_dir/o365enum
git clone https://github.com/0xZDH/o365spray $install_dir/o365spray
git clone https://github.com/0xZDH/Omnispray $install_dir/Omnispray
git clone https://github.com/dievus/Oh365UserFinder $install_dir/Oh365UserFinder
sudo mkdir -p $install_dir/exfil_exchange_mail
sudo chown $username:$username $install_dir/exfil_exchange_mail
wget https://raw.githubusercontent.com/rootsecdev/Azure-Red-Team/master/Tokens/exfil_exchange_mail.py -O $install_dir/exfil_exchange_mail/exfil_exchange_mail.py
# Install pip and pipx tools
pipx ensurepath --global
pipx install azure-cli
pipx install graphspy
pipx install "git+https://github.com/dirkjanm/ROADtools" --include-deps
pip install requests colorama
# Configure Docker to run under User Context
sudo usermod -aG docker $username
file_name=""
case $arch in
    x86_64)
        file_name="azurehound-linux-amd64.zip"
        ;;
    arm64 | aarch64)
        file_name="azurehound-linux-arm64.zip"
        ;;
    *)
        echo "Unsupported architecture: $arch"
        exit 1
        ;;
esac
# AzureHound
wget https://github.com/BloodHoundAD/AzureHound/releases/download/v2.1.7/${file_name} -O azurehound.zip
unzip azurehound.zip
mkdir azure_hound
mv ./azurehound azure_hound/
rm azurehound.zip
# Install BloodHoundCE
mkdir -p $install_dir/BloodhoundCE
curl https://raw.githubusercontent.com/SpecterOps/BloodHound/main/examples/docker-compose/docker-compose.yml -o /opt/mcrtp_bootcamp_tools/BloodhoundCE/docker-compose.yml
# Create symbolic links for tools
ln -s $install_dir/AADInternals /usr/local/bin/aadinternals
ln -s $install_dir/GraphRunner /usr/local/bin/graphrunner
ln -s $install_dir/TokenTacticsV2 /usr/local/bin/tokentactics
ln -s $install_dir/MFASweep /usr/local/bin/mfasweep
ln -s $install_dir/AzSubEnum /usr/local/bin/azsubenum
ln -s $install_dir/basicblobfinder /usr/local/bin/basicblobfinder
ln -s $install_dir/o365enum /usr/local/bin/o365enum
ln -s $install_dir/o365spray /usr/local/bin/o365spray
ln -s $install_dir/Omnispray /usr/local/bin/omnispray
ln -s $install_dir/Oh365UserFinder /usr/local/bin/oh365userfinder
ln -s $install_dir/exfil_exchange_mail/exfil_exchange_mail.py /usr/local/bin/exfil_exchange_mail
ln -s $install_dir/azure_hound/azurehound /usr/local/bin/azurehound
# Post Installation Activities
# Clear the terminal
clear
# Define color variables
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
# Instructions
echo -e "${BLUE}Bloodhound CE docker-compose file has been downloaded to /opt/mcrtp_bootcamp_tools/BloodhoundCE${NC}"
echo -e "${YELLOW}To launch Bloodhound CE, navigate to${NC} ${GREEN}"/opt/mcrtp_bootcamp_tools/BloodhoundCE/"${NC} ${YELLOW}and run the following command:${NC} ${GREEN}docker-compose up${NC}"
echo -e "${YELLOW}Note the randomly generated password from the logs, as you'll need it for the first login.${NC}"
echo -e "${YELLOW}To retrieve the password, use the command:${NC} ${GREEN}docker logs bloodhoundce_bloodhound_1 2>&1 | grep \"Initial Password Set To:\"${NC}"
echo -e "${YELLOW}Access the GUI at:${NC} ${GREEN}http://localhost:8080/ui/login${NC}. ${YELLOW}Ensure no other applications (e.g., BurpSuite) are using this port.${NC}"
echo -e "${YELLOW}Login using the username:${NC} ${GREEN}admin${NC} ${YELLOW}and the randomly generated password from the logs.${NC}"
echo -e "${YELLOW}Reboot your machine, then run the following command to update your PATH:${NC} ${GREEN}pipx ensurepath${NC}. ${YELLOW}Logout and log back in for changes to take effect.${NC}"
```
**Pimpmykali**
```Python
cd /tmp && git clone https://github.com/Dewalt-arch/pimpmykali && sudo bash pimpmykali/pimpmykali.sh
```
Optional
    
**pCloud**
    
````Python
firefox 'https://www.pcloud.com/how-to-install-pcloud-drive-linux.html?download=electron-64' && sleep 3 && cd ~/Downloads && chmod +x pcloud && ./pcloud
````
    
**syncthing service (bash script)**

```Bash
#!/bin/bash

SERVICE_FILE="/etc/systemd/system/syncthing.service"
echo "Creating Syncthing service file..."
sudo tee $SERVICE_FILE > /dev/null <<EOL
[Unit]
Description=Syncthing - Open Source Continuous File Synchronization
Documentation=man:syncthing(1)
After=network.target

[Service]
User=$USER
ExecStart=/usr/bin/syncthing serve --no-browser --gui-address=127.0.0.1:8384
Restart=on-failure
SuccessExitStatus=3 4
RestartForceExitStatus=3 4

[Install]
WantedBy=default.target
EOL
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload
echo "Enabling Syncthing to start at boot..."
sudo systemctl enable syncthing
echo "Starting Syncthing service..."
sudo systemctl start syncthing
echo "Checking Syncthing service status..."
sudo systemctl status syncthing
echo "Syncthing service setup complete!"
```