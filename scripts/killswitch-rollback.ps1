# killswitch-rollback.ps1 — 移除 killswitch 防火墙规则, 恢复默认 (需管理员)
# 任何时刻运行本脚本即可完全回退, 不影响其他防火墙规则。
$names = @("PF-Killswitch-<AppA>", "PF-Killswitch-<AppB>")  # 与 install 脚本保持一致
foreach ($n in $names) {
    $r = Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue
    if ($r) { Remove-NetFirewallRule -DisplayName $n; Write-Output "removed: $n" }
    else { Write-Output "not found: $n" }
}
Write-Output "rollback done"
