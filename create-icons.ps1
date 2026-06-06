Add-Type -AssemblyName System.Drawing
$src = New-Object System.Drawing.Bitmap("$PSScriptRoot\icons\icon128.png")

$img48 = New-Object System.Drawing.Bitmap(48, 48)
$g48 = [System.Drawing.Graphics]::FromImage($img48)
$g48.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g48.DrawImage($src, 0, 0, 48, 48)
$g48.Dispose()
$img48.Save("$PSScriptRoot\icons\icon48.png", [System.Drawing.Imaging.ImageFormat]::Png)
$img48.Dispose()

$img16 = New-Object System.Drawing.Bitmap(16, 16)
$g16 = [System.Drawing.Graphics]::FromImage($img16)
$g16.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g16.DrawImage($src, 0, 0, 16, 16)
$g16.Dispose()
$img16.Save("$PSScriptRoot\icons\icon16.png", [System.Drawing.Imaging.ImageFormat]::Png)
$img16.Dispose()

$src.Dispose()
Write-Host "Icons created successfully"
