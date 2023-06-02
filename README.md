# OpenReversa : A collaborative function identification tool for Ghidra

This work was inspired on the last year work [OpenFunctionID](https://github.com/Cyjanss/MasterThesis_Ghidra).


## Prerequisites
Before you proceed with the installation, ensure that you have the following prerequisites met:

- Compatible Operating System (Windows, macOS or Linux)
- A complete Ghidra installation (version 10.2.3 or higher)
- Active internet connection
## Download the latest version
- In Github, you can find the release where the extension is already built.
- You can also build the latest version yourself, see last section below.

## Installation Steps
To install the **OpenReversa**, please follow these steps:

1. Launch the **Ghidra** application on your system.

2. Access the Extensions Manager:

    - Once Ghidra is open, go to the "File" menu at the top and select "Install Extensions".
3. Locate **OpenReversa**:

    - In the Extensions Manager window, click on the "Add" button.
    - Browse to the location where you saved the file *ghidra_10.2.3_PUBLIC_XXXXXXXX_OpenReversa.zip*.
    - Select the file and click "Open" or "OK".
4. Restart Ghidra:

    - After the installation is complete, you will be prompted to restart Ghidra.
    - Save any unsaved work and close Ghidra.
    - Launch Ghidra again to complete the installation process.

5. Access the Extension:

    - Once Ghidra restarts, the installed extension should now be available for use.
    - Click the "Yes" button to configure the extension and check "OpenReversaPlugin".
    - Now you can access the extension's features through the "Tools" menu then "Function ID".

## Building the project
- Clicking on the "Code" button and selecting "Download ZIP" to download the repository as a ZIP file. Extract the ZIP file to a preferred location on your machine.
- Once the project has been extracted, build it with the `gradle buildExtension` command at the root of the "OpenReversa" folder.
- A new "dist" folder will be created containing a file named *ghidra_10.2.3_PUBLIC_XXXXXXXX_OpenReversa.zip*
- Now you are ready for the installation.

