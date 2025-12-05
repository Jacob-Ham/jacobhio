___

## How to passthrugh USB devices VirtualBox

1. Extension pack and VirtualBox versions must **match**. The former can be found via File > Preferences > Extensions and the latter via Help > About.
2. USB Controller must be enabled in the VM configuration options.
3. VBox Guest Additions must be installed on the guest VM. With the VM running, click Devices > Insert Guest Additions CD Image and run the VBoxWindowsAdditions executable.
4. The user running VirtualBox must be in the **vboxusers** group. At the command line, run `groups` to see what groups you are a member of. If vboxusers isn't in the list, run `sudo gpasswd -a $USER vboxusers` to add yourself then REBOOT.
5. At least one filter must be set up under Devices > USB > USB Settings. Clicking the top icon on the right (USB plug with solid blue dot) will create a 'universal' filter for any device. When the VM is running, you should now see a list when you go to Devices > USB that allows you to select devices to connect.



## New note structure
---
Add cleanup considerations for EVERYTHING
Add detection considerations for EVERYTHING