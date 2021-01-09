# Windows 10 Update Restart Blocker

*App to control forced restarts caused by the Windows update service & a custom patch for its vulnerability bug.*

### Description

This project and the [binary app](https://dennisbabkin.com/w10urb/) came out from the discovery of the [vulnerability in the update service](https://dennisbabkin.com/blog/?t=pwning-windows-updates-dll-hijacking-through-orphaned-dll) in Windows 10. We originally submitted this bug to Microsoft in September of 2020, but they refused to fix it. Thus we had no choice than to fix it ourselves. This project is the result of that.

We also discovered that the bug itself allowed us to give users an option to delay forced restarts that were caused by installation of Windows updates.

In total, we designed this app to do the following:

- To patch the [DLL hijack vulnerability](https://dennisbabkin.com/blog/?t=pwning-windows-updates-dll-hijacking-through-orphaned-dll) in the Windows update service.
- To provide ways for the users to delay forced restarts that are caused by installation of Windows updates.
- To let users pick how often they allow to be bothered with notifications of a pending restart.
- This app is provided with complete source code for the full transparency.

Read [this blog post](https://dennisbabkin.com/blog/?t=patching-bugs-windows-update-service-dll-hijack-patch) for additional details about the design of this project.

### Disclaimer

This app is designed to no longer function if the original manufacturer (Microsoft) fixes the mentioned vulnerability in the Windows Update Service.

### Manual

Check this app's [original manual](https://dennisbabkin.com/php/docs.php?what=w10urb) for details.

### Operation

This app utilizes the aforementioned vulnerability to halt a restart that is initiated by the Windows Update Service and lets the user choose what to do by diplaying this message box:

![Alt text](https://dennisbabkin.com/php/images/w10urb_rbt_atmpt.png "Reboot Attempt - Windows 10 Update Restart Blocker")

Additionally, the app exposes some settings for the user to control how often they want to see the popup shown above:

![Alt text](https://dennisbabkin.com/php/images/w10urb_sttgs.png "Windows 10 Update Restart Blocker - Settings window")

The binary app comes with its own MSI installer that can be used for the installation on a standalone Windows 10 system, or for the installation on multiple computers joined into a domain via a Group Policy Object (GPO) in a Windows Active Directory.

### Release Build

If you don't want to build and code-sign this app yourself, you can download the latest [release build here](https://dennisbabkin.com/w10urb/).

### Build Instructions

To build this project you will need the following:

- **Microsoft Visual Studio 2017, Community Edition** - needed to build the main binaries. For that open the following solution file:

  `Win10RestartBlocker.sln`
  
  To build the binaries all at once go to `Build` -> `Batch Build` and use `Rebuild` command for the following projects & configurations:
  
  - caW10URBInstaller - Release - Win32
  - ShellChromeAPI - Release - Win32
  - ShellChromeAPI - Release - x64
  - Win10RestartBlockerUI - Release - Win32
  - Win10RestartBlockerUI - Release - x64
  
- **Microsoft Visual Studio 2010** - needed to build the WiX MSI installer. For that open the following solution file:

  `Installer/w10rbInstaller/w10urbInstaller.sln`

  Make sure to download and install the [WiX Toolset library](https://wixtoolset.org/) to build the installer.
  
  To build the MSI installer, make sure to build the binaries from the `Win10RestartBlocker.sln` solution first. Then go to `Build` -> `Rebuild Solution` to build the MSI.
  



--------------

Submit suggestions & bug reports [here](https://www.dennisbabkin.com/sfb/?what=bug&name=Windows+10+Update+Restart+Blocker&ver=Github).
