# ShellGen

PowerShell script to generate ShellCode in various formats

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/ShellGen/main/ShellGen.ps1')
```
```
ShellGen -x64 -Command "cmd /k ipconfig" -OutputFormat "Encrypted"
```
```
ShellGen -x64 -Command "cmd /k ipconfig" -OutputFormat "Raw" -OutputFilePath C:\Users\Senna\Desktop\whoami.bin
```

### Output Formats

```
Raw, ps1, Hex, C, vba, csharp, Encrypted, UUID
```

### Architecture

```
x64, x86
```

### Feed a raw shellcode file

```
Shellgen -RawFile "C:\Users\User\Desktop\file.bin" -OutputFormat vba
```
