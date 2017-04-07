QUICK START TO BitRock InstallBuilder
-------------------------------------

Launch InstallBuilder.

In the InstallBuilder main menu select File -> Open Project -> From File...

Select Aegis.xml

Project will be loaded.

In the left column you will see five main project tabs.

In the "Product Details" tab you can setup the package information like product name, product version, vendor name etc.

![alt text](ProductDetails.png)

In the "Files" tab you can set up the project files destination paths.

Aegis files must be installed in /usr/local/

Startup Aegis plist file must be installed in /Library/LaunchDaemons/

"Aegis Google Chrome extension" json file must be installed in /Library/Application Support/Google/Chrome/External Extensions/

"Aegis Safari extension" file must be installed in Program Files (Mac OS X) 

![alt text](Files.png)

"Advanced" tab allows you to create menu with the installations parameters and custom scripts. 

Select "Advanced" in the "Parameters" folder to edit Aegis configuration menu.

Select "Post-installation Actions" to edit the installer scripts. There are:

    - script to update Aegis config file

    - script to install Aegis Safari extension

Select "Post-uninstallation Actions" to edit the uninstaller scripts. There are:

    - script to uninstall Aegis Safari extension

![alt text](Advanced.png)

After all actions will be done click "Build" in the InstallBuilder main menu.

After a successful build the installation package will be located in "/Applications/BitRock InstallBuilder/output/" folder.
