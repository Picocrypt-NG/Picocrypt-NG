<a href="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-windows.yml"><img src="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-windows.yml/badge.svg"></a>
<a href="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-windows-legacy.yml"><img src="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-windows-legacy.yml/badge.svg"></a>
<a href="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-macos.yml"><img src="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-macos.yml/badge.svg"></a>
<a href="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-linux.yml"><img src="https://github.com/Picocrypt-NG/Picocrypt-NG/actions/workflows/build-linux.yml/badge.svg"></a>

<p align="center"><img align="center" src="/images/logo.png" width="512" alt="Picocrypt NG"></p> 

Picocrypt NG (new generation) is a very small (hence <i>Pico</i>), very simple, yet very secure encryption tool that you can use to protect your files. It's designed to be the <i>go-to</i> tool for file encryption, with a focus on security, simplicity, and reliability. Picocrypt NG uses the secure XChaCha20 cipher and the Argon2id key derivation function to provide a high level of security.

<br>
<p align="center"><img align="center" src="/images/screenshot.png" width="318" alt="Picocrypt NG"></p>

<!--  DO NOT REMOVE (but you can add more lines)  -->
# History

Picocrypt NG is a community-developed continuation of the archived [Picocrypt](https://github.com/Picocrypt) project.

*The original Picocrypt author does not endorse, develop, nor support Picocrypt NG.*

When referencing Picocrypt NG, please always include the "NG" suffix to ensure distinction.
<!--/ DO NOT REMOVE  -->

# Downloads

ℹ️ **You are highly recommended to read through the [Features](https://github.com/Picocrypt-NG/Picocrypt-NG?tab=readme-ov-file#features) section below to fully understand the features and limitations of Picocrypt NG before using it.** ℹ️

Make sure to only download Picocrypt NG from this repository to ensure that you get the authentic and backdoor-free Picocrypt NG. When sharing Picocrypt NG with others, be sure to link to this repository to prevent any confusion.

## Windows
**Windows 10/11:** Download the latest, standalone, and portable executable <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG.exe">here</a>.

**Windows 7/8 (Legacy Systems):** If you're running Windows 7, Windows 8, or systems without OpenGL support, download the <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG-Legacy-Windows.zip">Legacy Build</a> instead. This version includes:
- Compiled with [go-legacy-win7](https://github.com/thongtech/go-legacy-win7) for Windows 7/8 compatibility
- Bundled Mesa3D software OpenGL renderer (no GPU or graphics drivers required)
- Keep all files in the extracted folder together

⚠️ **Note:** The legacy build uses CPU-based software rendering and may be slower than the standard build. Only use it if you're on Windows 7/8 or experiencing graphics-related issues on older systems.

If your antivirus flags Picocrypt NG as a virus, please report it as a false positive to help everyone.

## macOS
Download Picocrypt NG <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG.dmg">here</a>, open the container, and drag Picocrypt NG to your Applications. You will need to manually trust the app from a terminal if macOS prevents you from opening it:
```
xattr -d com.apple.quarantine /Applications/Picocrypt-NG.app
```

Note: the macOS app is built for Apple silicon only. If you're still on Intel, you can build from source.

## Linux
Download the raw binary <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG">here</a> (you may need the packages below). Alternatively, try the <a href="https://github.com/Picocrypt-NG/Picocrypt-NG/releases/latest/download/Picocrypt-NG.deb">.deb</a> or <a href="https://flathub.org/apps/io.github.picocrypt-ng.Picocrypt-NG">Flatpak</a>.
```
sudo apt install -y libc6 libgcc-s1 libgl1 libgtk-3-0 libstdc++6 libx11-6
```

## CLI
A command-line interface is available for Picocrypt NG <a href="https://github.com/Picocrypt-NG/CLI">here</a>. It can encrypt and decrypt files, folders, and glob patterns, and supports paranoid mode and Reed-Solomon encoding. You can use it on systems that don't have a GUI or can't run the GUI app.

## Web
A functionally limited web app is available <a href="https://picocrypt-ng.github.io/">here</a> which allows you to encrypt and decrypt standard Picocrypt NG volumes (no advanced features or keyfiles) on any modern browser, including mobile devices. It's a simple, future-proof way to securely encrypt files that should work indefinitely due to the web's stable nature. Note that you can only encrypt/decrypt single files up to a maximum size of 512 MiB.

# Comparison
Here's how Picocrypt NG compares to other popular encryption tools.

|                | Picocrypt NG   | VeraCrypt      | 7-Zip GUI      | BitLocker      | Cryptomator    |
| -------------- | -------------- | -------------- | -------------- | -------------- | -------------- |
| Free           |✅ Yes         |✅ Yes          |✅ Yes         |✅ Bundled      |✅ Yes         |
| Open Source    |✅ GPLv3       |✅ Multi        |✅ LGPL        |❌ No           |✅ GPLv3       |
| Cross-Platform |✅ Yes         |✅ Yes          |❌ No          |❌ No           |✅ Yes         |
| Size           |✅ 3 MiB       |❌ 20 MiB       |✅ 2 MiB       |✅ N/A          |❌ 50 MiB      |
| Portable       |✅ Yes         |✅ Yes          |❌ No          |✅ Yes          |❌ No          |
| Permissions    |✅ None        |❌ Admin        |❌ Admin       |❌ Admin        |❌ Admin       |
| Ease-Of-Use    |✅ Easy        |❌ Hard         |✅ Easy        |✅ Easy         |🟧 Medium      |
| Cipher         |✅ XChaCha20   |✅ AES-256      |✅ AES-256     |🟧 AES-128      |✅ AES-256     |
| Key Derivation |✅ Argon2      |🟧 PBKDF2       |❌ SHA-256     |❓ Unknown      |✅ Scrypt      |
| Data Integrity |✅ Always      |❌ No           |❌ No          |❓ Unknown      |✅ Always      |
| Deniability    |✅ Supported   |✅ Supported    |❌ No          |❌ No           |❌ No          |
| Reed-Solomon   |✅ Yes         |❌ No           |❌ No          |❌ No           |❌ No          |
| Compression    |✅ Yes         |❌ No           |✅ Yes         |✅ Yes          |❌ No          |
| Telemetry      |✅ None        |✅ None         |✅ None        |❓ Unknown      |✅ None        |
| Audited        |✅ [Historically](https://github.com/Picocrypt/storage/blob/main/Picocrypt.Audit.Report.pdf)       |✅ Yes          |❌ No          |❓ Unknown      |✅ Yes         |

Keep in mind that while Picocrypt NG does most things better than other tools, it's not a one-size-fits-all and doesn't try to be. There are use cases such as full-disk encryption where VeraCrypt and BitLocker would be a better (and the only) choice. So while Picocrypt NG is a great choice for the majority of people doing file encryption, you should still do your own research and use what's best for you.

# Features
Picocrypt NG is a very simple tool and most users will intuitively understand how to use it in a few seconds. On a basic level, simply dropping your files, entering a password, and hitting Encrypt is all that's needed to encrypt your files. Dropping the output back into Picocrypt NG, entering the password, and hitting Decrypt is all that's needed to decrypt those files. Pretty simple, right?

While being simple, Picocrypt NG also strives to be powerful in the hands of knowledgeable and advanced users. Thus, there are some additional options that you may use to suit your needs. Read through their descriptions carefully as some of them can be complex to use correctly.
<ul>
	<li><strong>Password generator</strong>: Picocrypt NG provides a secure password generator that you can use to create cryptographically secure passwords. You can customize the password length, as well as the types of characters to include.</li>
	<li><strong>Comments</strong>: Use this to store <strong>non-sensitive</strong> text along with the volume (<strong>it won't be encrypted</strong> and simply can't be by design). For example, you can put a description of the file you're encrypting before sending it to someone. When the person you sent it to drops the volume into Picocrypt NG, your description will be shown to that person. Or, if you're backing up personal files, you can give a description of the volume's contents so you can quickly remind yourself without having to fully decrypt. Since comments are neither encrypted nor authenticated, it can be freely read and modified by an attacker. <strong>Thus, it should only be used for non-sensitive, informational purposes in trusted environments.</strong></li>
	<li><strong>Keyfiles</strong>: Picocrypt NG supports the use of keyfiles as an additional form of authentication (or the only form of authentication). Any file can be used as a keyfile, and a secure keyfile generator is provided for convenience. Not only can you use multiple keyfiles, but you can also require the correct order of keyfiles to be present for a successful decryption to occur. A particularly good use case of multiple keyfiles is creating a shared volume, where each person holds a keyfile, and all of them (and their keyfiles) must be present to decrypt the shared volume. By checking the "Require correct order" box and dropping your keyfile in last, you can also ensure that you'll always be the one clicking the Decrypt button. <strong>Use the keyfile generator whenever possible for the best security.</strong></li>
	<li><strong>Paranoid mode</strong>: Using this mode will encrypt your data with both XChaCha20 and Serpent in a cascade fashion, and use HMAC-SHA3 to authenticate data instead of BLAKE2b. Argon2 parameters will be increased significantly as well. This is recommended for protecting top-secret files and provides the highest level of practical security attainable. For a hacker to break into your encrypted data, both the XChaCha20 cipher and the Serpent cipher must be broken, assuming you've chosen a good password. It's safe to say that in this mode, your files are impossible to crack. Keep in mind, however, that this mode is slower and isn't really necessary unless you're a government agent with classified data or a whistleblower under threat.</li>
	<li><strong>Reed-Solomon</strong>: This feature is very useful if you are planning to archive important data on a cloud provider or external medium for a long time. If checked, Picocrypt NG will use the Reed-Solomon error correction code to add 8 extra bytes for every 128 bytes of data to prevent file corruption. This means that up to ~3% of your file can corrupt and Picocrypt NG will still be able to correct the errors and decrypt your files with no corruption. Of course, if your file corrupts very badly (e.g., you dropped your hard drive), Picocrypt NG won't be able to fully recover your files, but it will try its best to recover what it can. Note that this option will slow down encryption and decryption speeds significantly.</li>
	<li><strong>Force decrypt</strong>: Picocrypt NG automatically checks for file integrity upon decryption. If the file has been modified or is corrupted, Picocrypt NG will automatically delete the output for the user's safety. If you would like to override these safeguards, check this option. Also, if this option is checked and the Reed-Solomon feature was used on the encrypted volume, Picocrypt NG will attempt to recover as much of the file as possible during decryption.</li>
	<li><strong>Split into chunks</strong>: Don't feel like dealing with gargantuan files? No worries! With Picocrypt NG, you can choose to split your output file into custom-sized chunks, so large files can become more manageable and easier to upload to cloud providers. Simply choose a unit (KiB, MiB, GiB, or TiB) and enter your desired chunk size for that unit. To decrypt the chunks, simply drag one of them into Picocrypt NG and the chunks will be automatically recombined during decryption.</li>
	<li><strong>Compress files</strong>: By default, Picocrypt NG uses a zip file with no compression to quickly merge files together when encrypting multiple files. If you would like to compress these files, however, simply check this box and the standard Deflate compression algorithm will be applied during encryption.</li>
	<li><strong>Deniability</strong>: Picocrypt NG volumes typically follow an easily recognizable header format. However, if you want to hide the fact that you are encrypting your files, enabling this option will provide you with plausible deniability. The output volume will indistinguishable from a stream of random bytes, and no one can prove it is a volume without the correct password. This can be useful in an authoritarian country where the only way to transport your files safely is if they don't "exist" in the first place. Keep in mind that this mode slows down encryption and decryption speeds, requires you to manually rename the volume afterward, renders comments useless, and also voids the extra security precautions of the paranoid mode, so you should only use it if absolutely necessary. <strong>If you've never heard of plausible deniability, this feature is not for you.</strong></li>
	<li><strong>Recursively</strong>: If you want to encrypt and/or decrypt a large set of files individually, this option will tell Picocrypt NG to go through every recursive file that you drop in and encrypt/decrypt it separately. This is useful, for example, if you are encrypting thousands of large documents and want to be able to decrypt any one of them in particular without having to download and decrypt the entire set of documents. <strong>Keep in mind that this is a very complex feature that should only be used if you know what you are doing.</strong></li>
</ul>

# Security
For more information on how Picocrypt NG handles cryptography, see <a href="Internals.md">Internals</a> for the technical details.

<strong>Picocrypt NG operates under the assumption that the host machine it is running on is safe and trusted. If that is not the case, no piece of software will be secure, and you will have much bigger problems to worry about. As such, Picocrypt NG is designed for the offline security of volumes and does not attempt to protect against side-channel analysis.</strong>

# FAQ
**Does the "Delete files" feature shred files?**

No, it doesn't shred any files and just deletes them as your file manager would. On modern storage mediums like SSDs, there is no such thing as shredding a file since wear leveling makes it impossible to overwrite a particular sector. Thus, to prevent giving users a false sense of security, Picocrypt NG doesn't include any shredding features at all.

**Is Picocrypt NG quantum-secure?**

Yes, Picocrypt NG is secure against quantum computers. All of the cryptography used in Picocrypt NG works off of a private key, and private-key cryptography is considered to be resistant against all current and future developments, including quantum computers.

# Acknowledgements
Thank you to the significant contributors on [Open Collective](https://opencollective.com/picocrypt) who helped secure the original Picocrypt project's audit:
<ul>
	<li><strong>Mikołaj ($1674)</strong></li>
	<li><strong>Guest ($842)</strong></li>
	<li><strong>YellowNight ($818)</strong></li>
	<li>Incognito ($135)</li>
	<li>akp ($98)</li>
	<li>JC ($90)</li>
	<li>evelian ($50)</li>
	<li>jp26 ($50)</li>
	<li>guest-116103ad ($50)</li>
	<li>Guest ($27)</li>
	<li>Gittan Pade ($25)</li>
	<li>Pokabu ($20)</li>
	<li>oli ($20)</li>
	<li>Bright ($20)</li>
	<li>Incognito ($20)</li>
	<li>Guest ($20)</li>
	<li>JokiBlue ($20)</li>
	<li>Guest ($20)</li>
	<li>Markus ($15)</li>
	<li>EN ($15)</li>
	<li>Guest ($13)</li>
	<li>Tybbs ($10)</li>
	<li>N. Chin ($10)</li>
	<li>Manjot ($10)</li>
	<li>Phil P. ($10)</li>
	<li>Raymond ($10)</li>
	<li>Cohen ($10)</li>
	<li>EuA ($10)</li>
	<li>geevade ($10)</li>
	<li>Guest ($10)</li>
	<li>Hilebrinest ($10)</li>
	<li>gabu.gu ($10)</li>
	<li>Boat ($10)</li>
	<li>Guest ($10)</li>
</ul>
<!-- Last updated July 12, 2024 -->
