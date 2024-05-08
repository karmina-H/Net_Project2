param (
    [int]$portNumber
)

# 해당 포트를 닫음
New-NetFirewallRule -DisplayName "Block Port $portNumber" -Direction Inbound -LocalPort $portNumber -Protocol TCP -Action Block

# 10초 동안 대기
Start-Sleep -Seconds 10

# 해당 포트를 다시 염
Remove-NetFirewallRule -DisplayName "Block Port $portNumber"