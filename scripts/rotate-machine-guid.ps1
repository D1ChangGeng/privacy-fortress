# MachineGuid 轮换: 备份 -> 换新随机GUID -> 回读验证
# 用途: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid 是常见的设备指纹源,
#       普通权限可读。轮换为随机 GUID 切断"同一设备"跨应用关联。
# 注意: 需提权(管理员)。部分软件的授权绑定 MachineGuid, 轮换后可能需要重新激活。
# 用法: 右键"使用PowerShell运行" 或 管理员终端: powershell -File rotate-machine-guid.ps1
$log = Join-Path $PSScriptRoot "rotate-machine-guid-log.txt"
"=== $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File $log

$key = "HKLM:\SOFTWARE\Microsoft\Cryptography"
$prop = "MachineGuid"
$old = (Get-ItemProperty -Path $key -Name $prop -ErrorAction Stop).$prop
"原 MachineGuid: $old" | Out-File $log -Append

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$bak = "$key.$prop.bak-$stamp"
New-Item -Path $bak -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $bak -Name "backup" -Value $old
"备份至注册表项: $bak" | Out-File $log -Append

$new = [guid]::NewGuid().ToString()
Set-ItemProperty -Path $key -Name $prop -Value $new
$verify = (Get-ItemProperty -Path $key -Name $prop).$prop
if ($verify -eq $new) {
    "新 MachineGuid: $new (轮换成功, 已回读确认)" | Out-File $log -Append
} else {
    "回读不一致! 当前值: $verify" | Out-File $log -Append
}
"提示: 如某软件授权失效, 从备份 $bak 恢复原值即可。" | Out-File $log -Append
