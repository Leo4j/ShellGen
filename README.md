# ShellGen

PowerShell script to generate ShellCode in various formats

```
ShellGen -x64 -CmdCommand "echo ciao > C:\Users\Rob_Commando\Desktop\ciao.txt" -OutputFormat "Raw" -OutputFilePath C:\Users\Senna\Desktop\whoami.bin
```
```
ShellGen -x64 -PwshCommand "echo ciao > C:\Users\Rob_Commando\Desktop\ciao.txt" -OutputFormat "Raw" -OutputFilePath C:\Users\Senna\Desktop\whoami.bin
```
```
ShellGen -x64 -B64PwshCommand "JABwA...AKAApAA==" -OutputFilePath C:\Users\Senna\Desktop\whoami.bin
```

### Output Formats

```
Raw, ps1, Hex, C, vba, csharp
```

### Architecture

```
x64, x86
```
