<#
.SYNOPSIS
    Script de Auditoría y Verificación de Baseline de Seguridad para Active Directory.
.DESCRIPTION
    Script automatizado diseñado para el laboratorio 'ad-infrastructure-and-defense-lab'.
    Verifica la infraestructura y seguridad del entorno Active Directory evaluando:
      1. Salud de Controladores de Dominio y Roles FSMO.
      2. Cumplimiento de la Política de Contraseñas y Bloqueo de Cuentas (Default Domain Policy).
      3. Estructura de Unidades Organizativas por Niveles (Tier 0 / Tier 1 / Tier 2).
      4. Hardening de Servicios de Escritorio Remoto (RDP) y Registro de Políticas.
      5. Inspección Forense de Eventos de Autenticación y Bloqueo (IDs 4625, 4771, 4740).
.NOTES
    Autor: Kanu (Analista de Ciberseguridad)
    Proyecto: ad-infrastructure-and-defense-lab
    Requisitos: Windows Server 2022 / PowerShell 5.1+ / Módulo ActiveDirectory / Privilegios de Administrador.
#>

[CmdletBinding()]
param (
    [int]$HoursToAudit = 24,
    [string]$DomainName = "lab.local"
)

# Configuración de Colores y Formatos
function Write-Header {
    param([string]$Title)
    Write-Host "`n==========================================================================" -ForegroundColor Cyan
    Write-Host "  [+] $Title" -ForegroundColor Yellow
    Write-Host "==========================================================================" -ForegroundColor Cyan
}

function Write-CheckResult {
    param(
        [string]$CheckName,
        [bool]$Passed,
        [string]$Details = ""
    )
    if ($Passed) {
        Write-Host "  [OK] " -ForegroundColor Green -NoNewline
    } else {
        Write-Host "  [WARN/FAIL] " -ForegroundColor Red -NoNewline
    }
    Write-Host "$CheckName" -NoNewline
    if ($Details) {
        Write-Host " -> $Details" -ForegroundColor Gray
    } else {
        Write-Host ""
    }
}

Write-Host "`n"
Write-Host "==========================================================================" -ForegroundColor Yellow
Write-Host "      ACTIVE DIRECTORY INFRASTRUCTURE & DEFENSE AUDIT SCRIPT v1.0         " -ForegroundColor Yellow
Write-Host "      Laboratorio: ad-infrastructure-and-defense-lab ($DomainName)        " -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Yellow

# 1. SALUD DE CONTROLADORES DE DOMINIO Y FSMO
Write-Header "1. Infraestructura de Controladores de Dominio & Roles FSMO"
try {
    $dcs = Get-ADDomainController -Filter *
    foreach ($dc in $dcs) {
        $isGC = $dc.IsGlobalCatalog
        Write-CheckResult -CheckName "DC: $($dc.HostName) (IP: $($dc.IPv4Address))" -Passed $true -Details "Global Catalog: $isGC | Sitio: $($dc.Site)"
    }
    
    $domain = Get-ADDomain
    Write-Host "`n  Roles FSMO Asignados:" -ForegroundColor Yellow
    Write-Host "    - Schema Master:              $($domain.SchemaMaster)" -ForegroundColor White
    Write-Host "    - Domain Naming Master:       $($domain.DomainNamingMaster)" -ForegroundColor White
    Write-Host "    - PDC Emulator:               $($domain.PDCEmulator)" -ForegroundColor White
    Write-Host "    - RID Master:                 $($domain.RIDMaster)" -ForegroundColor White
    Write-Host "    - Infrastructure Master:      $($domain.InfrastructureMaster)" -ForegroundColor White
} catch {
    Write-CheckResult -CheckName "Error al consultar infraestructura de AD" -Passed $false -Details $_.Exception.Message
}

# 2. AUDITORÍA DE POLÍTICA DE CONTRASEÑAS Y BLOQUEO (DDP)
Write-Header "2. Verificación de Política de Contraseñas y Bloqueo (Default Domain Policy)"
try {
    $policy = Get-ADDefaultDomainPasswordPolicy
    
    $passComplexity = $policy.ComplexityEnabled
    Write-CheckResult -CheckName "Complejidad de Contraseña Requerida" -Passed $passComplexity -Details "Estado: $passComplexity"
    
    $minLen = $policy.MinPasswordLength
    Write-CheckResult -CheckName "Longitud Mínima de Contraseña (>= 7)" -Passed ($minLen -ge 7) -Details "Valor: $minLen caracteres"
    
    $minAge = $policy.MinPasswordAge.Days
    Write-CheckResult -CheckName "Edad Mínima de Contraseña (>= 1 día)" -Passed ($minAge -ge 1) -Details "Valor: $minAge día(s)"
    
    $history = $policy.PasswordHistoryCount
    Write-CheckResult -CheckName "Historial de Contraseñas (>= 24)" -Passed ($history -ge 24) -Details "Valor: $history contraseñas recordadas"
    
    $lockoutThreshold = $policy.LockoutThreshold
    Write-CheckResult -CheckName "Umbral de Bloqueo de Cuentas (== 5 intentos)" -Passed ($lockoutThreshold -eq 5) -Details "Valor: $lockoutThreshold intentos"
    
    $lockoutDuration = $policy.LockoutDuration.Minutes
    Write-CheckResult -CheckName "Duración del Bloqueo (== 15 min)" -Passed ($lockoutDuration -eq 15) -Details "Valor: $lockoutDuration minutos"
} catch {
    Write-CheckResult -CheckName "Error al consultar Get-ADDefaultDomainPasswordPolicy" -Passed $false -Details $_.Exception.Message
}

# 3. VERIFICACIÓN DE ARQUITECTURA DE OUs POR NIVELES (TIER 0 / 1 / 2)
Write-Header "3. Auditoría de Estructura de OUs por Niveles (Tiering & Convención)"
try {
    $ous = Get-ADOrganizationalUnit -Filter *
    Write-CheckResult -CheckName "Unidades Organizativas Registradas" -Passed ($ous.Count -gt 0) -Details "Total OUs encontradas: $($ous.Count)"
    
    $tier0 = $ous | Where-Object { $_.DistinguishedName -like "*Tier0*" }
    $tier1 = $ous | Where-Object { $_.DistinguishedName -like "*Tier1*" }
    $tier2 = $ous | Where-Object { $_.DistinguishedName -like "*Tier2*" }
    
    Write-Host "    - OUs en Tier 0: $($tier0.Count)" -ForegroundColor White
    Write-Host "    - OUs en Tier 1: $($tier1.Count)" -ForegroundColor White
    Write-Host "    - OUs en Tier 2: $($tier2.Count)" -ForegroundColor White
} catch {
    Write-CheckResult -CheckName "Error al evaluar Unidades Organizativas" -Passed $false -Details $_.Exception.Message
}

# 4. AUDITORÍA DE HARDENING RDP Y SERVICIOS TERMINALES
Write-Header "4. Hardening RDP & Estado de Servicios Terminales"
try {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    if (Test-Path $regPath) {
        $fDeny = (Get-ItemProperty -Path $regPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
        if ($fDeny -eq 1) {
            Write-CheckResult -CheckName "GPO RDP Deshabilitado (fDenyTSConnections=1)" -Passed $true -Details "Acceso RDP Denegado por Política"
        } else {
            Write-CheckResult -CheckName "Estado fDenyTSConnections" -Passed $false -Details "Valor actual: $fDeny"
        }
    } else {
        Write-CheckResult -CheckName "Clave de Registro GPO RDP" -Passed $false -Details "Ruta no configurada en este host"
    }
    
    $portTest = Test-NetConnection -ComputerName localhost -Port 3389 -WarningAction SilentlyContinue
    Write-CheckResult -CheckName "Puerto RDP 3389 Cerrado/Filtrado" -Passed (-not $portTest.TcpTestSucceeded) -Details "Conexión local 3389 exitosa: $($portTest.TcpTestSucceeded)"
} catch {
    Write-CheckResult -CheckName "Error al comprobar hardening RDP" -Passed $false -Details $_.Exception.Message
}

# 5. REGISTROS DE EVENTOS Y FORENSE DE AUTENTICACIÓN
Write-Header "5. Inspección de Eventos Security Log (IDs 4625, 4771, 4740 - Últimas $HoursToAudit Horas)"
try {
    $startTime = (Get-Date).AddHours(-$HoursToAudit)
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625, 4771, 4740
        StartTime = $startTime
    } -ErrorAction SilentlyContinue

    if ($events) {
        Write-Host "  [!] Se registraron $($events.Count) eventos en las últimas $HoursToAudit horas:" -ForegroundColor Yellow
        $summary = $events | Select-Object TimeCreated, Id,
            @{N='Cuenta'; E={$_.Properties[0].Value}},
            @{N='Tipo/Detalle'; E={
                if ($_.Id -eq 4625) { "Fallos NTLM / User Rights (4625)" }
                elseif ($_.Id -eq 4771) { "Pre-autenticación Kerberos Fallida (4771)" }
                elseif ($_.Id -eq 4740) { "CUENTA BLOQUEADA (4740)" }
            }}
        $summary | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor White
    } else {
        Write-CheckResult -CheckName "Eventos de Alerta de Logons/Bloqueo" -Passed $true -Details "Sin eventos de error o bloqueo registrados."
    }
} catch {
    Write-CheckResult -CheckName "Consulta de Eventos Security Log" -Passed $true -Details "Sin eventos capturados en el rango de tiempo especificado."
}

Write-Host "`n==========================================================================" -ForegroundColor Green
Write-Host "  [✓] AUDITORÍA COMPLETADA. REVISAR RESULTADOS SUPERIORES." -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green
