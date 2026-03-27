# ============================================================
# VARIABLES GLOBALES
# ============================================================
$Global:DomainName   = "dominio.local"
$Global:DomainAdmin  = "DOMINIO\Administrator"
$Global:DomainPass   = "Admin@12345!"
$Global:DnsServer    = "222.222.222.222"
$Global:SidNoCuates  = "S-1-5-21-2205334512-381440921-4159792505-1604"
$Global:SidAdmins    = "S-1-5-32-544"
$Global:AppLockerXml = "C:\AppLocker_Local.xml"

# ---------------------------------------- Funciones ----------------------------------------

function Get-InterfazRed {
    Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "127.*"} |
        Select-Object IPAddress, InterfaceAlias | Format-Table
    $iface = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object {
        $ip = Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ip -and $ip.IPAddress -like "222.222.222.*") { $_ }
    } | Select-Object -First 1
    if (-not $iface) { $iface = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1 }
    Write-Host "Interfaz detectada: $($iface.Name)" -ForegroundColor Green
    return $iface
}

function Set-DnsHaciasDC {
    param([Parameter(Mandatory)][object]$Interfaz)
    Set-DnsClientServerAddress -InterfaceIndex $Interfaz.InterfaceIndex -ServerAddresses $Global:DnsServer
    Write-Host "DNS configurado -> $Global:DnsServer" -ForegroundColor Green
}

function Test-ResolucionDominio {
    Start-Sleep -Seconds 2
    $resolve = Resolve-DnsName -Name $Global:DomainName -Server $Global:DnsServer -ErrorAction SilentlyContinue
    if ($resolve) { Write-Host "Resolucion DNS: OK" -ForegroundColor Green; return $true }
    else          { Write-Host "ERROR: No resuelve $Global:DomainName" -ForegroundColor Red; return $false }
}

function Invoke-UnirDominio {
    $iface = Get-InterfazRed
    Set-DnsHaciasDC -Interfaz $iface
    if (-not (Test-ResolucionDominio)) { Write-Host "Abortando: sin resolucion DNS." -ForegroundColor Red; return }
    $cred = New-Object System.Management.Automation.PSCredential(
        $Global:DomainAdmin,
        (ConvertTo-SecureString $Global:DomainPass -AsPlainText -Force)
    )
    Add-Computer -DomainName $Global:DomainName -Credential $cred -Force -ErrorAction Stop
    Write-Host "Unido al dominio. Reiniciando en 3 segundos..." -ForegroundColor Green
    Start-Sleep -Seconds 3
    Restart-Computer -Force
}

function Get-HashesNotepad {
    $notepad1 = "$env:SystemRoot\System32\notepad.exe"
    $notepad2 = "$env:SystemRoot\SysWOW64\notepad.exe"
    $hash1 = (Get-AppLockerFileInformation -Path $notepad1).Hash.HashDataString
    $len1  = (Get-Item $notepad1).Length
    $hash2 = (Get-AppLockerFileInformation -Path $notepad2).Hash.HashDataString
    $len2  = (Get-Item $notepad2).Length
    Write-Host "Hash System32 : $hash1" -ForegroundColor Cyan
    Write-Host "Hash SysWOW64 : $hash2" -ForegroundColor Cyan
    return @{ Hash1 = $hash1; Len1 = $len1; Hash2 = $hash2; Len2 = $len2 }
}

function New-AppLockerXml {
    param([Parameter(Mandatory)][hashtable]$Hashes)
    $xml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FileHashRule Id="b2e2d5b5-1a2b-4c3d-8e4f-5a6b7c8d9e0f"
                  Name="BLOQUEAR Notepad System32 - NoCuates"
                  Description="Bloquea notepad.exe System32 por hash para NoCuates aunque sea renombrado"
                  UserOrGroupSid="$($Global:SidNoCuates)" Action="Deny">
      <Conditions><FileHashCondition>
        <FileHash Type="SHA256" Data="$($Hashes.Hash1)" SourceFileName="notepad.exe" SourceFileLength="$($Hashes.Len1)" />
      </FileHashCondition></Conditions>
    </FileHashRule>
    <FileHashRule Id="c5d6e7f8-a9b0-1234-cdef-567890abcdef"
                  Name="BLOQUEAR Notepad SysWOW64 - NoCuates"
                  Description="Bloquea notepad.exe SysWOW64 por hash para NoCuates aunque sea renombrado"
                  UserOrGroupSid="$($Global:SidNoCuates)" Action="Deny">
      <Conditions><FileHashCondition>
        <FileHash Type="SHA256" Data="$($Hashes.Hash2)" SourceFileName="notepad.exe" SourceFileLength="$($Hashes.Len2)" />
      </FileHashCondition></Conditions>
    </FileHashRule>
    <FilePathRule Id="a1b2c3d4-e5f6-7890-abcd-ef1234567890" Name="Permitir Windows"
                  Description="Permite ejecutables de Windows para todos (incluye notepad para Cuates)"
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="b2c3d4e5-f6a7-8901-bcde-f12345678901" Name="Permitir Program Files"
                  Description="Permite ejecutables de Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="Admins total"
                  Description="Administradores sin restriccion" UserOrGroupSid="$($Global:SidAdmins)" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="NotConfigured" />
  <RuleCollection Type="Msi"    EnforcementMode="NotConfigured" />
  <RuleCollection Type="Dll"    EnforcementMode="NotConfigured" />
  <RuleCollection Type="Appx"   EnforcementMode="NotConfigured" />
</AppLockerPolicy>
"@
    $xml | Out-File $Global:AppLockerXml -Encoding UTF8 -Force
    Write-Host "XML guardado en $Global:AppLockerXml" -ForegroundColor Green
}

function Enable-AppIDSvc {
    Set-Service   AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service AppIDSvc -ErrorAction SilentlyContinue
    Write-Host "AppIDSvc: $((Get-Service AppIDSvc).Status)" 
}

function Set-AppLockerPolicyLocal {
    $basePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
    if (Test-Path $basePath) { Remove-Item -Path $basePath -Recurse -Force }
    New-Item -Path $basePath -Force | Out-Null
    Set-AppLockerPolicy -XmlPolicy $Global:AppLockerXml
    Restart-Service AppIDSvc -Force
    Start-Sleep -Seconds 3
    Write-Host "AppLocker aplicado" 
}

