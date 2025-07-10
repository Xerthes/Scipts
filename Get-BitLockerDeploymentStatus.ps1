<#
.SYNOPSIS
    Rapport HTML du statut de déploiement BitLocker pour tous les ordinateurs de l’Active Directory.

.DESCRIPTION
    Ce script collecte l’état de chiffrement BitLocker sur tous les ordinateurs AD (volume C:) 
    et génère un rapport HTML contenant :
    - Nom du PC
    - Statut de protection
    - Pourcentage de chiffrement
    - Type de protecteur
    - Présence de la clé de récupération dans AD

.NOTES
    Auteur : ChatGPT (inspiré de Loïc Veirman)
#>

Import-Module ActiveDirectory

$computers = Get-ADComputer -Filter {Enabled -eq $true -and OperatingSystem -like "*Windows*"} -Property Name, OperatingSystem | Sort-Object Name
$report = @()

foreach ($computer in $computers) {
    $name = $computer.Name
    Write-Host "🔍 Analyse de $name..." -ForegroundColor Cyan

    try {
        $bitlockerInfo = Invoke-Command -ComputerName $name -ScriptBlock {
            try {
                $vol = Get-BitLockerVolume -MountPoint "C:"
                if ($null -eq $vol) { return $null }

                $protectors = $vol.KeyProtector | ForEach-Object { $_.KeyProtectorType } | Sort-Object -Unique -join ", "
                $recovery = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }

                return @{
                    ProtectionStatus = $vol.ProtectionStatus
                    EncryptionStatus = $vol.EncryptionPercentage
                    KeyProtector     = $protectors
                    HasRecoveryKey   = if ($recovery) { $true } else { $false }
                }
            } catch {
                return $null
            }
        } -ErrorAction Stop

        if ($bitlockerInfo) {
            $adRecoveryKey = try {
                $adObject = Get-ADComputer $name -Properties 'msFVE-RecoveryPassword'
                if ($adObject.'msFVE-RecoveryPassword') { "Oui" } else { "Non" }
            } catch { "Inconnu" }

            $report += [PSCustomObject]@{
                Ordinateur        = $name
                OS                = $computer.OperatingSystem
                ProtectionBitLocker = if ($bitlockerInfo.ProtectionStatus -eq 'On') { "Activé" } else { "Désactivé" }
                PourcentageChiffré = "$($bitlockerInfo.EncryptionStatus)%"
                Protecteurs         = $bitlockerInfo.KeyProtector
                CléDansAD           = $adRecoveryKey
            }
        } else {
            $report += [PSCustomObject]@{
                Ordinateur        = $name
                OS                = $computer.OperatingSystem
                ProtectionBitLocker = "Inaccessible"
                PourcentageChiffré = "Inconnu"
                Protecteurs         = "Erreur"
                CléDansAD           = "Inconnu"
            }
        }
    } catch {
        $report += [PSCustomObject]@{
            Ordinateur        = $name
            OS                = $computer.OperatingSystem
            ProtectionBitLocker = "Erreur"
            PourcentageChiffré = "Erreur"
            Protecteurs         = "Erreur"
            CléDansAD           = "Erreur"
        }
    }
}

# 💾 Génération HTML
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$outputPath = "BitLockerDeploymentReport_$timestamp.html"

$report | Sort-Object Ordinateur | ConvertTo-Html -Title "Rapport Déploiement BitLocker" -PreContent "<h1>Rapport Déploiement BitLocker</h1><p>Généré le $timestamp</p>" -Property Ordinateur, OS, ProtectionBitLocker, PourcentageChiffré, Protecteurs, CléDansAD |
    Out-File -Encoding UTF8 $outputPath

Write-Host "`n✅ Rapport généré : $outputPath" -ForegroundColor Green
