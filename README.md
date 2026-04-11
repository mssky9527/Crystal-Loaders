# Crystal Loaders

This repo contains a couple of PIC loaders and a custom sleepmask COFF for use with Cobalt Strike.  They are basic implementations where custom evasion tradecraft must be weaved in using [Crystal Palace](https://tradecraftgarden.org/).

## Usage

1. Download the Crystal Palace [Release](https://tradecraftgarden.org/crystalpalace.html) distrubtion.
2. Extract the tar archive and copy `crystalpalace.jar` to the same directory as `cobaltstrike.exe` (the client).
3. Load `loaders.cna` to use the custom loaders (there are loaders for both Beacon and postex DLLs).
4. Load `mask.cna` to use the custom sleepmask.

## Notes

You can use just the loaders, just the sleepmask, or both together.  Each are compatible with the [4.12 BUD](https://github.com/Cobalt-Strike/bof-vs/blob/dd6addd1f9b4bc637b63247d67552709f0c59ddf/BOF-Template/beacon.h) structures, so in theory, you can mix and match these with other custom loaders and sleepmasks (assuming they are also 4.12-compatible).  This project is not backwards-compatible with pre-4.12.
