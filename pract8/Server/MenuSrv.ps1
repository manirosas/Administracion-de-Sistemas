. .\FunSrv.ps1
#Requires -RunAsAdministrator
# ============================================================
# MENU INTERACTIVO
# ============================================================
function Show-Menu {
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "   TAREA 08 - SERVIDOR - MENU PRINCIPAL" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1]  FASE 1 - Preparacion (crear CSV)" -ForegroundColor White
    Write-Host "  [2]  FASE 2 - Instalar AD DS  ** REINICIA EL SERVIDOR **" -ForegroundColor Yellow
    Write-Host "  [3]  FASE 3 - Configurar dominio (post-reinicio)" -ForegroundColor White
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [4]  Solo: Crear OUs y Grupos" -ForegroundColor Gray
    Write-Host "  [5]  Solo: Crear Share Homes" -ForegroundColor Gray
    Write-Host "  [6]  Solo: Crear usuarios desde CSV" -ForegroundColor Gray
    Write-Host "  [7]  Solo: Aplicar Logon Hours" -ForegroundColor Gray
    Write-Host "  [8]  Solo: Crear GPO cierre por horario" -ForegroundColor Gray
    Write-Host "  [9]  Solo: Configurar cuotas FSRM" -ForegroundColor Gray
    Write-Host "  [10] Solo: Configurar File Screening FSRM" -ForegroundColor Gray
    Write-Host "  [11] Solo: Habilitar AppIDSvc" -ForegroundColor Gray
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [12] Verificacion final del dominio" -ForegroundColor Green
    Write-Host "  [0]  Salir" -ForegroundColor Red
    Write-Host ""
}

do {
    Show-Menu
    $opcion = Read-Host "  Selecciona una opcion"

    switch ($opcion) {
        "1"  {
            Write-Host "`n>> Ejecutando Fase 1..." -ForegroundColor Cyan
            Invoke-Preparacion
        }
        "2"  {
            Write-Host "`n>> Ejecutando Fase 2 - El servidor se REINICIARA..." -ForegroundColor Yellow
            $confirmar = Read-Host "   Confirmar? (S/N)"
            if ($confirmar -eq "S") { Invoke-InstalarAD }
        }
        "3"  {
            Write-Host "`n>> Ejecutando Fase 3 - Configuracion post-reinicio..." -ForegroundColor Cyan
            Invoke-ConfigurarDominio
        }
        "4"  {
            Write-Host "`n>> Creando OUs y Grupos..." -ForegroundColor Cyan
            Import-Module ActiveDirectory
            New-OUsYGrupos
        }
        "5"  {
            Write-Host "`n>> Creando Share Homes..." -ForegroundColor Cyan
            New-ShareHomes
        }
        "6"  {
            Write-Host "`n>> Creando usuarios desde CSV..." -ForegroundColor Cyan
            Import-Module ActiveDirectory
            $usuarios = Import-Csv $Global:CsvPath
            New-UsuariosDesdeCSV -Usuarios $usuarios
        }
        "7"  {
            Write-Host "`n>> Aplicando Logon Hours..." -ForegroundColor Cyan
            Import-Module ActiveDirectory
            $usuarios = Import-Csv $Global:CsvPath
            Set-HorariosLogon -Usuarios $usuarios
        }
        "8"  {
            Write-Host "`n>> Creando GPO de cierre por horario..." -ForegroundColor Cyan
            Import-Module GroupPolicy
            New-GPOCierreHorario
        }
        "9"  {
            Write-Host "`n>> Configurando cuotas FSRM..." -ForegroundColor Cyan
            Import-Module FileServerResourceManager
            $usuarios = Import-Csv $Global:CsvPath
            New-CuotasFSRM -Usuarios $usuarios
        }
        "10" {
            Write-Host "`n>> Configurando File Screening..." -ForegroundColor Cyan
            Import-Module FileServerResourceManager
            $usuarios = Import-Csv $Global:CsvPath
            New-FileScreeningFSRM -Usuarios $usuarios
        }
        "11" {
            Write-Host "`n>> Habilitando AppIDSvc..." -ForegroundColor Cyan
            Enable-AppIDSvc
        }
        "12" {
            Write-Host "`n>> Verificando estado del dominio..." -ForegroundColor Green
            Import-Module ActiveDirectory, GroupPolicy, FileServerResourceManager
            Invoke-VerificacionFinal
        }
        "0"  {
            Write-Host "`nSaliendo..." -ForegroundColor Red
            break
        }
        default {
            Write-Host "`nOpcion no valida." -ForegroundColor Red
        }
    }

    if ($opcion -ne "0") {
        Write-Host "`nPresiona ENTER para volver al menu..." -ForegroundColor DarkGray
        Read-Host | Out-Null
    }

} while ($opcion -ne "0")
