AEGIS installer for OS X, Windows and Linux
-------------------------------------------

Launch InstallBuilder.

In the InstallBuilder main menu select File -> Open Project -> From File...

Select Aegis.xml

Project will be loaded.

In the left column you will see five main project tabs.

In the "Product Details" tab you can setup the package information like product name, product version, vendor name etc.

![alt text](files-github/ProductDetails.png)

In the "Files" tab you can set up the project files destination paths.

OS X:

    Aegis files (usr-local.zip) must be installed in Program Files (Mac OS X). It's archive of /usr/local/ directory, which will be unzipped in Post-installation Actions

    "Aegis Safari extension" file must be installed in Program Files (Mac OS X)

    "Aegis Google Chrome extension" json file must be installed in /Library/Application Support/Google/Chrome/External Extensions/

    "Aegis Mozilla Firefox extension" file must be installed in /Applications/Firefox.app/Contents/Resources/browser/extensions/

WINDOWS:

    Aegis files must be installed in "Program Files (Windows)" and "ProgramData (Windows)"

    "Aegis Mozilla Firefox extension" file must be installed in %APPDATA%\Mozilla\Extensions
    
    "Aegis Edge extension" must be installed in "Program Files (Windows)" and "ProgramData (Windows)"

LINUX:
    
    Aegis files must be installed in the root of filesystem (/usr directory)

    "Aegis Google Chrome extension" json file must be installed in the root of filesystem (/opt directory)

    "Aegis Mozilla Firefox extension" file must be installed in /usr/lib/firefox-addons/extensions

![alt text](files-github/Files.png)

"Advanced" tab allows you to create menu with the installations parameters and custom scripts.

Select "Post-installation Actions" to edit the installer scripts. There are:

    - script to unzip Aegis files (usr-local.zip) to /usr/local (OS X)

    - scripts to update Aegis config file (Windows and OS X)

    - script to create and run Aegis service (OS X)

    - script to install Aegis Safari extension (OS X)

    - script to install Aegis Google Chrome extension (Windows)

    - script to install Aegis Internet Explorer extension (Windows)    
    
    - script to install Aegis Edge extension (Windows)    

    - script to create and run Aegis service (Windows)

    - script to make aegis file executable (Lunix)

Select "Post-uninstallation Actions" to edit the uninstaller scripts. There are:

    - scripts to stop and remove Aegis service (OS X)

    - scripts to uninstall Aegis files (OS X)

    - script to uninstall Aegis Safari extension (OS X)

    - script to uninstall Aegis Google Chrome extension (Windows)

    - script to uninstall Aegis Internet Explorer extension (Windows)

Select "Advanced" in the "Parameters" folder to edit Aegis configuration menu.

![alt text](files-github/Advanced.png)

After all actions will be done click "Build" in the InstallBuilder main menu.

After a successful build the installation package will be located in "/Applications/BitRock InstallBuilder/output/" folder.







Below is the instructions on how to modify the source code of installer for installation of plugins. Screenshot are provided.

After the “extensions” are published in the stores, the installers may be edited.

First, clone the git repository at:
https://github.com/SageAxcess/installer-osx.git
Then, select the branch dev_2017

Now, editing can begin. We will show an example of the installation of adblock extension, because it is already present in all of the shops. Your plugins will be installed in a similar way.

1) Run InstallBuilder and, using in File-> Open Project-> From file, select the project file named Aegis.xml, located in the previously cloned directory, at installer-osx\InstallBuilder\Aegis.xml.

2) Select Advanced section on InstallBuilder side panel

![alt text](files-github/screenshot1.png)

3) Scroll down the settings tree and locate the element named "Ready to Install Actions". 

![alt text](files-github/screenshot2.png)

Tree elements that need to be edited are outlined with the red rectangle.

Prior to editing, download the published extensions from the stores.

Safari

In your case, there is no need to download safari extension, because you already have it. (The one we provided earlier). You will need to have it on the server at 
https://aegis-osx.s3.amazonaws.com/AEGIS.safariextz


Chrome
There is no need to download the plugin for Chrome, instead, go to https://chrome.google.com/webstore/category/extensions in the Chrome browser.

Search for the “extension” in the store and select it. You should be able to see the page similar to the one on the screenshot (screenshot contains the adblock example page). 

![alt text](files-github/screenshot3.png)

Next, in the address bar, copy your extension’s guid (in this example it is underlined with a red line, gighmmpiobklfepjocnamgkkbiglidom). Now you have everything for installing Chrome “extension”.

Firefox
Prior to downloading the “extension” for Firefox, open the following folder:

 C:\Users\<your username>\AppData\Roaming\Mozilla\Firefox\Profiles\<random name>\extensions

This folder contains all the “extensions” installed. If the folder is not empty, you will need to take note of all extensions contained in it, in order to determine which of the extensions is yours after you have installed it. The one which will appear after the installation and was not in the folder before the installation, is your extension.

In order to download the “extension” for Firefox, use the following link, https://addons.mozilla.org/en-US/firefox/. Then, in the Firefox store, find your extension and install it.

Now, in the folder  C:\Users\<your username>\AppData\Roaming\Mozilla\Firefox\Profiles\<random name>\extensions, search for "<your extension>.xpi". (see the screenshot based on the adblock example).

![alt text](files-github/screenshot4.png)

In case of adblock, it will be the file "{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}.xpi". 

You will need to place this file "<your extension>.xpi" to your server here: https://aegis-osx.s3.amazonaws.com/<your extension>.xpi (In the adblock example, it will be https://aegis-osx.s3.amazonaws.com/{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}.xpi)
Now, you have everything for the installation of Firefox “extension”.


Edge

In order to install an Edge extension, it must first be signed with a certificate. Then, the certificate is installed on a user computer.
To generate certificate that will be used to sing <your extension>.appx, you need to install relevant utilities. They are included into Windows SDK, which can be downloaded from here https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk

After installation, execute the following commands in PowerShell:
"C:\Program Files (x86)\Windows Kits\8.1\bin\x64\MakeCert" /n "CN=1DB4D603-BFD1-4FAB-8D9F-F048340841C0" /r /h 0 /eku "1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.13" /e "12/31/2018" /sv MyKey.pvk MyKey.cer
"C:\Program Files (x86)\Windows Kits\8.1\bin\x64\Pvk2Pfx" /pvk MyKey.pvk /pi "123qwe" /spc MyKey.cer /pfx MyKey.pfx /po "123qwe"
"C:\Program Files (x86)\Windows Kits\8.1\bin\x64\signtool.exe" sign /fd sha256  /f MyKey.pfx /p 123qwe AEGISAgent.appx

After executing these commands, you will have "MyKey.cer" certificate and signed Edge extension "AEGISAgent.appx"
Place you “MyKey.cer” certificate into your installer’s directory, at path .\installer-osx\InstallBuilder\Content\win. Now you have everything to install the Edge extension.



4) Specify the links from which the extensions will be downloaded in InstallBuilder.

Safari:
For Safary, double click on the element shown in the screenshot below:

![alt text](files-github/screenshot13.png)

The following dialog box will open.

![alt text](files-github/screenshot14.png)

Enter the link to your safari extension, which you have uploaded to the server earlier, into the field outlined with the red rectangle and click “OK”. 

Firefox:

For Firefox, double click on the element shown in the screenshot below

![alt text](files-github/screenshot15.png)

The following dialog box will open

![alt text](files-github/screenshot16.png)

Enter the link to your Firefox extension, which you have uploaded to the server earlier, into the field outlined with the red rectangle and click “OK”. 

Next, double click on the element shown on the screenshot below

![alt text](files-github/screenshot17.png)

The following dialog box will open

![alt text](files-github/screenshot18.png)

Enter the link to your Firefox extension, which you have uploaded to the server earlier, into the field outlined with the red rectangle and click “OK”. 

Double click on the field shown in the screenshot below

![alt text](files-github/screenshot19.png)

The following dialog box will open:

![alt text](files-github/screenshot20.png)


Enter the link to your Edge extension, which you have uploaded to the server earlier, into the field in the red rectangle and click “OK”. 


In the Filename field in the red rectangle, the text ${installdir}/aegis.appx needs to be edited

Replace aegis.appx with the name of you extension, in our case, the text will look like this ${installdir}/EyeoGmbH.AdblockPlus_0.9.9.0_neutral__d55gg7py3s0m0.Appx

Click “OK” once done.

5) Next, you will need to edit Post-installation Actions sections

![alt text](files-github/screenshot21.png)

OSX

First, edit installation section for OSX, this section is outlined with the red rectangle on the screenshot below.

![alt text](files-github/screenshot22.png)

Double click on “Run cp” element.

![alt text](files-github/screenshot23.png)

The following dialog box will open:

![alt text](files-github/screenshot24.png)

You will need to edit “Program Arguments” field. In it, aegis.xpi text needs to be replaced with the name of the Firefox “extension” you have downloaded from Firefox store.


-f ${installdir}/aegis.xpi /Applications/Firefox.app/Contents/Resources/browser/extensions/<name of your Firefox extension downloaded from the store>.xpi


In our Adblock example, the text will look like this:
-f ${installdir}/aegis.xpi /Applications/Firefox.app/Contents/Resources/browser/extensions/{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}.xpi

Click “OK” after editing.

Double click on the field shown on the screenshot.

![alt text](files-github/screenshot25.png)

The following dialog box will open:

![alt text](files-github/screenshot26.png)

You will need to edit “Path” field outlined with the red rectangle. The following string needs to be modified:

/Library/Application Support/Google/Chrome/External Extensions/aegis_chrome_id.json

Change aegis_chrome_id substring to guid of your Chrome extension.

In our adblock example, guid looks like this “gighmmpiobklfepjocnamgkkbiglidom” (how to get it is described above in section 3). The example of such string for adblock

/Library/Application Support/Google/Chrome/External Extensions/ gighmmpiobklfepjocnamgkkbiglidom.json

Click “OK” once done.

Windows

Double click on the field shown on the screenshot below

![alt text](files-github/screenshot27.png)

The following dialog box will open:

![alt text](files-github/screenshot28.png)

“Destination” field, outlined with the red rectangle, needs to be edited. The string in it needs to be changed, so that aegis.xpi is replaced with the name of Firefox “extension” you have downloaded from the Firefox store.


${user_home_directory}\AppData\Roaming\Mozilla\Extensions\{ec8030f7-c20a-464f-9b0e-13a3a9e97384}\<name of your Firefox extension downloaded from the store >.xpi

In the Adblock exmpale, the string will look like this:
${user_home_directory}\AppData\Roaming\Mozilla\Extensions\{ec8030f7-c20a-464f-9b0e-13a3a9e97384}\{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}.xpi

Click “OK” once done.



Double click on the field shown on the screenshot.

![alt text](files-github/screenshot29.png)

The dialog window will open:

![alt text](files-github/screenshot30.png)

The field “Program Arguments” in the red rectangle needs to be edited. The following string must be edited:

/C reg -command add HKEY_LOCAL_MACHINE\Software\Wow6432Node\Google\Chrome\Extensions\aegix_chrome_id /v update_url /d https://clients2.google.com/service/update2/crx /f


Replace aegix_chrome_id substring with the guid of your Chrome extension.

In the adblock example, guid looks like this “gighmmpiobklfepjocnamgkkbiglidom” (how to get it is described above in section 3). The example of such string for adblock

/C reg -command add HKEY_LOCAL_MACHINE\Software\Wow6432Node\Google\Chrome\Extensions\ gighmmpiobklfepjocnamgkkbiglidom /v update_url /d https://clients2.google.com/service/update2/crx /f

Click “OK” once done.


Double click on the field shown on the screenshot

![alt text](files-github/screenshot31.png)

The following dialog window will open:

![alt text](files-github/screenshot32.png)

“Program Arguments” field, outlined with the red rectangle, needs to be edited. The following string in it needs to be changed:
:
/install "${installdir}\MyKey.cer" "${installdir}\AEGISAgentSigned.appx"

Change AEGISAgentSigned.appx substring to the name of Edge extension download previously.

Click “OK” once done.



6) To build the installer, click on the “Build” button as shown on the screenshot

![alt text](files-github/screenshot33.png)

After the build process is finished, you will find your installer at the path shown on the screenshot

![alt text](files-github/screenshot34.png)

The installer path will be different in the building process for OSX, however it will be displayed in place of the Windows path on the screenshot above.

Since Edge extensions can only be installed from the store, when installing on a clean computer, the extension will be installed, but not displayed in the list of browser extensions. However, if the extension has already been installed in Edge and was removed, it will appear in the list of browser extension after the installation.

