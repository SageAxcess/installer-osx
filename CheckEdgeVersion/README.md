CheckEdgeVersion is used for checking the version of Edge browser, in installation of Edge extensions. VisualStudio2017 is required to build it. In order to build the project, run CheckEdgeVersion.sln and press F7 key. After that you will find CheckEdgeVersion.exe in CheckEdgeVersion\Release directory. Place this file into the directory installer-osx\InstallBuilder\Content\win

CheckEdgeVersion.exe accepts the following parameters
/install "certificate path" "path to <your extension>.appx"
"/minver" "version to check"
