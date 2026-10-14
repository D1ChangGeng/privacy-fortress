# killswitch-install.ps1 — AI 客户端防火墙 killswitch 安装脚本 (需管理员/UAC 一次)
# 效果: 目标 exe 仅允许连接 127.0.0.1(本地代理口) + 198.18.0.0/15(TUN fake-ip 段),
#       其余 IPv4 + 全部 IPv6 出站一律拒绝。
# 用途: "不小心关掉代理/TUN/系统代理"场景 fail-closed——应用只报"连不上", 永不裸连泄露真实IP。
# 注意: Windows 防火墙 -Program 不支持中段通配符(仅尾通配), MSIX 商店应用版本目录会随自动更新变化,
#       必须填精确路径; 版本漂移由每日巡检 killswitch 哨兵检测, FAIL 时重跑本脚本刷新。
# 回退: killswitch-rollback.ps1
$log = "<workspace>\guard\killswitch-install.log"
"" | Out-File $log

# ==== 按目标环境修改: 显示名 + 目标程序精确路径 ====
$targets = @(
    @{ Name = "PF-Killswitch-<AppA>"; Program = "C:\Program Files\WindowsApps\<PkgA>_<version>_<arch>__<pfid>\app\<AppA>.exe" },
    @{ Name = "PF-Killswitch-<AppB>"; Program = "C:\Program Files\WindowsApps\<PkgB>_<version>_<arch>__<pfid>\app\<AppB>.exe" }
)
# 允许段 = 198.18.0.0/15; 阻止 = 其余全部 IPv4 + 全部 IPv6 (回环 127.0.0.1 被防火墙豁免, 无需放行)
$blockedV4 = @("0.0.0.0-198.17.255.255", "198.20.0.0-255.255.255.255")
$blockedV6 = @("::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")

foreach ($t in $targets) {
    if (-not (Test-Path $t.Program)) { "SKIP(not found): $($t.Name) $($t.Program)" | Out-File $log -Append; continue }
    Get-NetFirewallRule -DisplayName $t.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    try {
        New-NetFirewallRule -DisplayName $t.Name -Direction Outbound -Action Block -Protocol Any `
            -Program $t.Program -RemoteAddress ($blockedV4 + $blockedV6) `
            -Profile Any -Enabled True -ErrorAction Stop | Out-Null
        "OK: $($t.Name)" | Out-File $log -Append
    } catch {
        "FAIL: $($t.Name) -> $($_.Exception.Message)" | Out-File $log -Append
    }
}
foreach ($t in $targets) {
    $r = Get-NetFirewallRule -DisplayName $t.Name -ErrorAction SilentlyContinue
    if ($r) {
        ($r | Get-NetFirewallApplicationFilter).Program | ForEach-Object { "verify: $($t.Name) program=$_ enabled=$(($r | Select-Object -First 1).Enabled)" } | Out-File $log -Append
    } else {
        "verify: MISSING $($t.Name)" | Out-File $log -Append
    }
}
"install done" | Out-File $log -Append
