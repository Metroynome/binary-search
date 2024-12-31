# binary-search
## 100% made with ChatGPTv4.

A very specific tool for a very specifig purpose for a very specific set of games.

This tool was written to search through Ratchet and Clank: UYA (NTSC/PAL) files for a specific hex pattern and print the adddress of the pattern in the format of how they are needed for the `horizon-uya-patch`.

This can also work on Ratchet: Deadlocked/Gladiator as well.

The binary files need to be named as such:
`{region}.{mapId}.{mapName}.bin`

region: pal or ntsc
mapId: the corrisponding map id/number
mapName: the name of the map.

Example:
`pal.40.BakisiIsles.bin`

The result it finds will print out like such:
`{mapName} = {address}`