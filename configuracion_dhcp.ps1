function Instalar-DHCP-Idempotente {
	$feature = Get-WindowsFeature -Name DHCP

	if ($feature.Installed){
		Write-Host "El rol DHCP ya está instalado."
	}
	else {
		$resp= Read-Host "El rol DHCP no está instalado. ¿Deseas instalarlo? (s/n)"
		if ($resp -ne "s"){
			Write-Host "Instalación cancelada"
			return
		}
		Install-WindowsFeature DHCP -IncludeManagementTools
	}
	
	$autorizado = Get-DhcpServerInDC -ErrorAction SilentlyContinue |
		Where-Object { $_.DnsName -eq $env:COMPUTERNAME }
	
	if ($autorizado) {
		Write-Host "Servidor DHCP ya autorizado"
	}
	else {
		Add-DhcpServerInDC
		Write-Host "Sercidor DHCP autorizado"
	}
	Start-Service dhcpserver
}

function Validar-IP {
	param ($IP)

	if ($IP -notmatch '^(\d{1,3}\.){3}\d{1,3}$') { return $false }
	$octetos = $IP.Split('.')
	foreach ($o in $octetos) {
		if ([int]$o -lt 0 -or [int]$o -gt 255) {return $false }
	}
	
	if ($octetos[3] -eq 255) {return $false}
	if ($IP -eq "0.0.0.0" -or $IP -eq "127.0.0.1" -or $IP -eq "255.255.255.255") { return $false }

	return $true
}

function IP-A-Entero {
	param ($IP)
	$o = $IP.Split('.')
	return ([int64]$o[0] -shl 24) -bor
	       ([int64]$o[1] -shl 16) -bor
	       ([int64]$o[2] -shl 8) -bor
	       ([int64]$o[3])
}

function Prefijo-A-Mascara {
	param ([int]$Prefijo)
	
	if ($Prefijo -lt 0 -or $Prefijo -gt 32){
		throw "Prefijo inválido (0-32)"
	}	
	
	$bin = ("1" * $Prefijo).PadRight(32, "0")

	$octetos= $bin -split '(.{8})' | 
	Where-Object { $_ } |
	ForEach-Object { [Convert]::ToInt32($_, 2) }
	
	return ($octetos -join ".")
}

function Obtener-Prefijo-Automatico{
	param ($IP)
	$a = [int]($IP.Split('.')[0])
	if ($a -ge 1 -and $a -le 126) { return 8 }
	elseif ($a -ge 128 -and $a -le 191) { return 16 }
	else { return 24 }
}

function Asignar-IP-Servidor{
	param ($IP, $Prefijo)
	$if = Get-NetAdapter -Name "Ethernet 2" -ErrorAction SilentlyContinue
	
	if (-not $if){
		Write-Host "La interfaz Ethernet 2 no existe "
		return
	}
	Remove-NetIPAddress -InterfaceIndex $if.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

	New-NetIPAddress `
		-InterfaceIndex $if.ifIndex `
		-IPAddress $IP `
		-PrefixLength $Prefijo
}

function Configurar-DHCP {
	if (-not (Get-WindowsFeature DHCP).Installed) {
	Write-Host "El rol DHCP no está instalado"
	return
	}
	
	$ScopeName = Read-Host "Nombre del ambito"

	do { $IPStart = Read-Host "IP inicial"} until (Validar-IP $IPStart)
	do { $IPEnd = Read-Host "IP final"} until (Validar-IP $IPEnd)
	
	if ($IPStart -eq $IPEnd) {
		Write-Host "La IP inicial no puede ser igual a la final"
		return
	}

	if ((IP-A-Entero $IPStart) -ge (IP-A-Entero $IPEnd)) {
		Write-Host "La IP inicial debe ser menor que la final"
		return
	}
	
	$MascaraInput = Read-Host "Mascara (Enter para automatico)"

	if ([string]::IsNullOrWhiteSpace($MascaraInput)) {
		$Prefijo = Obtener-Prefijo-Automatico $IPStart
	}
	elseif ($MascaraInput -match '^\d{1,2}$') {
		$Prefijo = [int]$MascaraInput
	}
	else {
		$Prefijo = 24
	}

	$Mascara = Prefijo-A-Mascara $Prefijo

	$oct = $IPStart.Split('.')
	$Gateway = Read-Host "Gateway (Enter para automatico)"
	if ([string]::IsNullOrWhiteSpace($Gateway)) {
		$Gateway = "$($oct[0]).$($oct[1]).$($oct[2]).1"
	}

	do {
		$Lease = Read-Host "Tiempo de lease en segundos"
	} until ([int]::TryParse($Lease, [ref]$null) -and [int]$Lease -gt 0)

	$DNS1= Read-Host "DNS primario(opcional)"
	if ($DNS1 -and -not (Validar-IP $DNS1)) {Write-Host "DNS primario invalido"; return}

	$DNS2= Read-Host "DNS secundario(opcional)"
	if ($DNS2 -and -not (Validar-IP $DNS2)) {Write-Host "DNS secundario invalido"; return}

	Asignar-IP-Servidor -IP $IPStart -Prefijo $Prefijo
	
	$IPStartInt = IP-A-Entero $IPStart
	$IPClienteInt = $IPStartInt + 1
	
	$IPCliente = @(
		($IPClienteInt -shr 24) -band 255
		($IPClienteInt -shr 16) -band 255
		($IPClienteInt -shr 8) -band 255
		$IPClienteInt -band 255
	) -join "."
	
	Add-DhcpServerv4Scope `
		-Name $ScopeName `
		-StartRange $IPCliente `
		-EndRange $IPEnd `
		-SubnetMask $Mascara `
		-LeaseDuration ([TimeSpan]::FromSeconds($Lease)) `
		-State Active

	$ScopeID = (Get-DhcpServerv4Scope | Where-Object Name -eq $ScopeName).ScopeId
	
	$DnsList = @()
	if ($DNS1) { $DnsList += $DNS1 }
	if ($DNS2) { $DnsList += $DNS2 }

	if ($DnsList.Count -gt 0){
		Set-DhcpServerv4OptionValue -ScopeId $ScopeID -DnsServer $DnsList -Router $Gateway
	}
	else {	
		Set-DhcpServer4OptionValue -ScopeId $ScopeID -Router $Gateway
	}

	Restart-Service dhcpserver
	Write-Host "Ambito DHCP configurado correctamente"
}

do{
	Write-Host ""
	Write-Host "Administrador DHCP Windows Server"
	Write-Host "1) Instalacion idempotente del rol DHCP"
	Write-Host "2) Configurar DHCP"
	Write-Host "3) Reiniciar DHCP"
	Write-Host "4) Ver concesiones del DHCP"
	Write-Host "5) Salir"
	$op = Read-Host "Opcion"

	switch ($op) {
	"1" { Instalar-DHCP-Idempotente }
	"2" { Configurar-DHCP }
	"3" { Restart-Service dhcpserver }
	"4" { Get-DhcpServerv4Lease }
	"5" { exit }
	default { Write-Host "Opcion no valida" }
	}
} while ($true)  algo esta mal, no está asignando las ip pero si muestra que está activo y las ip disponibles 
