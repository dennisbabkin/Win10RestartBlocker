# Windows 10 Update Restart Blocker

*Control forced restarts caused by Windows Updates & custom patch for its vulnerability bug.*

### Description

This project and the [binary app](https://dennisbabkin.com/w10urb/) came out from the discovery of the [vulnerability in the update service](https://dennisbabkin.com/blog/?t=pwning-windows-updates-dll-hijacking-through-orphaned-dll) in Windows 10. We originally submitted this bug to Microsoft in September of 2020, but they refused to fix it. Thus we had no choice than to fix it ourselves. This project is the result of that.

In total, this program was designed to do the following:

- To patch the [DLL hijack vulnerability](https://dennisbabkin.com/blog/?t=pwning-windows-updates-dll-hijacking-through-orphaned-dll) in the Windows update service.
- To provide ways for the users to delay forced restarts that are caused by installation of Windows updates.
- To let users pick how often they allow to be bothered with notifications of a pending restart.
- This app is provided with complete source code for the full transparency.

### Disclaimer

This app is designed to no longer function if the original manufacturer (Microsoft) fixes the vulnerability in the Windows Update Service.

### Manual

Check this app's [original manual](https://dennisbabkin.com/php/docs.php?what=w10urb) for details.

### Operation

It basically utilizes the aforementioned vulnerability to halt a restart that is initiated by the Windows Update Service and lets user choose what to do by diplaying this message box:

![Alt text](https://dennisbabkin.com/php/images/w10urb_rbt_atmpt.png "Reboot Attempt - Windows 10 Update Restart Blocker")

Additionally, the app exposes some settings for the user to control how often that want to see the popup shown above:

![Alt text](https://dennisbabkin.com/php/images/w10urb_sttgs.png "Windows 10 Update Restart Blocker - Settings window")

The binary app comes with its own MSI installer that can be used for the installation on a standalone Windows 10 system, or for the installation on multiple computers joined into a domain via a Group Policy Object (GPO) in a Windows Active Directory.

### Release Build

If you don't want to build and code-sign this app yourself, you can download the latest [release build here](https://dennisbabkin.com/w10urb/).

### Build Instructions

To build this project you will need the following:

- **Microsoft Visual Studio 2017, Community Edition** - needed to build the main binaries. For that open the following solution file:

  `Win10RestartBlocker.sln`
  
- **Microsoft Visual Studio 2010** - needed to build the WiX MSI installer. For that open the following solution file:

  `Installer/w10rbInstaller/w10urbInstaller.sln`

  Make sure to download and install the [WiX Toolset library](https://wixtoolset.org/) to build the installer.
  



--------------

Submit suggestions & bug reports [here](https://www.dennisbabkin.com/sfb/?what=bug&name=Windows+10+Update+Restart+Blocker&ver=Github).
