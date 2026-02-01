<#
.SYNOPSIS
    PowerShell 5 SOCKS5 Proxy Server with GUI
.DESCRIPTION
    A userland SOCKS5 proxy server with Windows Forms GUI.
    Supports SOCKS5 CONNECT command (TCP proxying).
#>

# UTF-8 encoding (wrapped for GUI mode where console may not exist)
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }
$OutputEncoding = [System.Text.Encoding]::UTF8

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Global state
$script:Listener = $null
$script:Running = $false
$script:Jobs = [System.Collections.ArrayList]::new()
$script:LogQueue = [System.Collections.Queue]::Synchronized([System.Collections.Queue]::new())
$script:ConnectionCount = 0
$script:Runspaces = [System.Collections.ArrayList]::new()
$script:RunspacePool = $null

# SOCKS5 Constants
$script:SOCKS_VERSION = 0x05
$script:AUTH_NONE = 0x00
$script:AUTH_NO_ACCEPTABLE = 0xFF
$script:CMD_CONNECT = 0x01
$script:ATYP_IPV4 = 0x01
$script:ATYP_DOMAIN = 0x03
$script:ATYP_IPV6 = 0x04
$script:REP_SUCCESS = 0x00
$script:REP_GENERAL_FAILURE = 0x01
$script:REP_CONNECTION_REFUSED = 0x05
$script:REP_CMD_NOT_SUPPORTED = 0x07
$script:REP_ATYP_NOT_SUPPORTED = 0x08

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $script:LogQueue.Enqueue("[$timestamp] [$Level] $Message")
}

function Start-Socks5Proxy {
    param([int]$Port, [string]$BindAddress = "127.0.0.1")
    
    try {
        $script:RunspacePool = [runspacefactory]::CreateRunspacePool(1, 50)
        $script:RunspacePool.Open()
        
        $endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($BindAddress), $Port)
        $script:Listener = [System.Net.Sockets.TcpListener]::new($endpoint)
        $script:Listener.Start()
        $script:Running = $true
        
        Write-Log "SOCKS5 proxy started on ${BindAddress}:${Port}"
        
        # Start accept loop in background
        $acceptScript = {
            param($Listener, $LogQueue, $RunspacePool)
            
            $SOCKS_VERSION = 0x05
            $AUTH_NONE = 0x00
            $AUTH_NO_ACCEPTABLE = 0xFF
            $CMD_CONNECT = 0x01
            $ATYP_IPV4 = 0x01
            $ATYP_DOMAIN = 0x03
            $ATYP_IPV6 = 0x04
            $REP_SUCCESS = 0x00
            $REP_GENERAL_FAILURE = 0x01
            $REP_CONNECTION_REFUSED = 0x05
            $REP_CMD_NOT_SUPPORTED = 0x07
            $REP_ATYP_NOT_SUPPORTED = 0x08
            
            function Log($msg, $lvl = "INFO") {
                $ts = Get-Date -Format "HH:mm:ss"
                $LogQueue.Enqueue("[$ts] [$lvl] $msg")
            }
            
            while ($Listener.Server.IsBound) {
                try {
                    if (-not $Listener.Pending()) {
                        Start-Sleep -Milliseconds 100
                        continue
                    }
                    
                    $client = $Listener.AcceptTcpClient()
                    $clientEP = $client.Client.RemoteEndPoint.ToString()
                    Log "Connection from $clientEP"
                    
                    # Handle client in separate runspace
                    $ps = [powershell]::Create()
                    $ps.RunspacePool = $RunspacePool
                    
                    $handlerScript = {
                        param($Client, $LogQueue, $ClientEP)
                        
                        $SOCKS_VERSION = 0x05
                        $AUTH_NONE = 0x00
                        $CMD_CONNECT = 0x01
                        $ATYP_IPV4 = 0x01
                        $ATYP_DOMAIN = 0x03
                        $ATYP_IPV6 = 0x04
                        $REP_SUCCESS = 0x00
                        $REP_GENERAL_FAILURE = 0x01
                        $REP_CONNECTION_REFUSED = 0x05
                        $REP_CMD_NOT_SUPPORTED = 0x07
                        $REP_ATYP_NOT_SUPPORTED = 0x08
                        
                        function Log($msg, $lvl = "INFO") {
                            $ts = Get-Date -Format "HH:mm:ss"
                            $LogQueue.Enqueue("[$ts] [$lvl] $msg")
                        }
                        
                        $remote = $null
                        try {
                            $stream = $Client.GetStream()
                            $stream.ReadTimeout = 30000
                            $stream.WriteTimeout = 30000
                            $buffer = New-Object byte[] 1024
                            
                            # Read greeting
                            $read = $stream.Read($buffer, 0, 2)
                            if ($read -lt 2 -or $buffer[0] -ne $SOCKS_VERSION) {
                                Log "Invalid SOCKS version from $ClientEP" "WARN"
                                return
                            }
                            
                            $nmethods = $buffer[1]
                            $read = $stream.Read($buffer, 0, $nmethods)
                            
                            # Send auth method (no auth)
                            $response = [byte[]]@($SOCKS_VERSION, $AUTH_NONE)
                            $stream.Write($response, 0, 2)
                            
                            # Read connect request
                            $read = $stream.Read($buffer, 0, 4)
                            if ($read -lt 4) {
                                Log "Short read on connect request" "WARN"
                                return
                            }
                            
                            if ($buffer[1] -ne $CMD_CONNECT) {
                                $reply = [byte[]]@($SOCKS_VERSION, $REP_CMD_NOT_SUPPORTED, 0, $ATYP_IPV4, 0,0,0,0, 0,0)
                                $stream.Write($reply, 0, 10)
                                Log "Unsupported command from $ClientEP" "WARN"
                                return
                            }
                            
                            $atyp = $buffer[3]
                            $targetHost = ""
                            $targetPort = 0
                            
                            switch ($atyp) {
                                $ATYP_IPV4 {
                                    $read = $stream.Read($buffer, 0, 6)
                                    $targetHost = "$($buffer[0]).$($buffer[1]).$($buffer[2]).$($buffer[3])"
                                    $targetPort = ($buffer[4] -shl 8) + $buffer[5]
                                }
                                $ATYP_DOMAIN {
                                    $read = $stream.Read($buffer, 0, 1)
                                    $domainLen = $buffer[0]
                                    $read = $stream.Read($buffer, 0, $domainLen + 2)
                                    $targetHost = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $domainLen)
                                    $targetPort = ($buffer[$domainLen] -shl 8) + $buffer[$domainLen + 1]
                                }
                                $ATYP_IPV6 {
                                    $read = $stream.Read($buffer, 0, 18)
                                    $ipBytes = $buffer[0..15]
                                    $addr = [System.Net.IPAddress]::new($ipBytes)
                                    $targetHost = $addr.ToString()
                                    $targetPort = ($buffer[16] -shl 8) + $buffer[17]
                                }
                                default {
                                    $reply = [byte[]]@($SOCKS_VERSION, $REP_ATYP_NOT_SUPPORTED, 0, $ATYP_IPV4, 0,0,0,0, 0,0)
                                    $stream.Write($reply, 0, 10)
                                    return
                                }
                            }
                            
                            Log "CONNECT $targetHost`:$targetPort from $ClientEP"
                            
                            # Connect to target
                            try {
                                $remote = [System.Net.Sockets.TcpClient]::new()
                                $remote.Connect($targetHost, $targetPort)
                                
                                # Success reply
                                $localEP = $remote.Client.LocalEndPoint
                                $localBytes = $localEP.Address.GetAddressBytes()
                                $portHi = ($localEP.Port -shr 8) -band 0xFF
                                $portLo = $localEP.Port -band 0xFF
                                
                                $reply = [byte[]]@($SOCKS_VERSION, $REP_SUCCESS, 0, $ATYP_IPV4) + $localBytes + @($portHi, $portLo)
                                $stream.Write($reply, 0, $reply.Length)
                                
                                Log "Connected to $targetHost`:$targetPort"
                                
                                # Relay data
                                $remoteStream = $remote.GetStream()
                                $clientBuf = New-Object byte[] 8192
                                $remoteBuf = New-Object byte[] 8192
                                
                                $stream.ReadTimeout = 100
                                $remoteStream.ReadTimeout = 100
                                
                                while ($Client.Connected -and $remote.Connected) {
                                    $activity = $false
                                    
                                    if ($stream.DataAvailable) {
                                        try {
                                            $n = $stream.Read($clientBuf, 0, $clientBuf.Length)
                                            if ($n -gt 0) {
                                                $remoteStream.Write($clientBuf, 0, $n)
                                                $activity = $true
                                            } else { break }
                                        } catch [System.IO.IOException] { }
                                    }
                                    
                                    if ($remoteStream.DataAvailable) {
                                        try {
                                            $n = $remoteStream.Read($remoteBuf, 0, $remoteBuf.Length)
                                            if ($n -gt 0) {
                                                $stream.Write($remoteBuf, 0, $n)
                                                $activity = $true
                                            } else { break }
                                        } catch [System.IO.IOException] { }
                                    }
                                    
                                    if (-not $activity) {
                                        Start-Sleep -Milliseconds 10
                                    }
                                }
                            }
                            catch {
                                $reply = [byte[]]@($SOCKS_VERSION, $REP_CONNECTION_REFUSED, 0, $ATYP_IPV4, 0,0,0,0, 0,0)
                                $stream.Write($reply, 0, 10)
                                Log "Failed to connect to $targetHost`:$targetPort - $($_.Exception.Message)" "ERROR"
                            }
                        }
                        catch {
                            Log "Handler error: $($_.Exception.Message)" "ERROR"
                        }
                        finally {
                            if ($remote) { $remote.Close() }
                            $Client.Close()
                            Log "Closed connection from $ClientEP"
                        }
                    }
                    
                    [void]$ps.AddScript($handlerScript)
                    [void]$ps.AddArgument($client)
                    [void]$ps.AddArgument($LogQueue)
                    [void]$ps.AddArgument($clientEP)
                    
                    $handle = $ps.BeginInvoke()
                    
                } catch {
                    if ($_.Exception.Message -notmatch "blocking") {
                        Log "Accept error: $($_.Exception.Message)" "ERROR"
                    }
                }
            }
        }
        
        $ps = [powershell]::Create()
        $ps.RunspacePool = $script:RunspacePool
        [void]$ps.AddScript($acceptScript)
        [void]$ps.AddArgument($script:Listener)
        [void]$ps.AddArgument($script:LogQueue)
        [void]$ps.AddArgument($script:RunspacePool)
        
        $handle = $ps.BeginInvoke()
        [void]$script:Runspaces.Add(@{PS=$ps; Handle=$handle})
        
        return $true
    }
    catch {
        Write-Log "Failed to start: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Stop-Socks5Proxy {
    $script:Running = $false
    
    if ($script:Listener) {
        $script:Listener.Stop()
        $script:Listener = $null
    }
    
    foreach ($rs in $script:Runspaces) {
        $rs.PS.Stop()
        $rs.PS.Dispose()
    }
    $script:Runspaces.Clear()
    
    if ($script:RunspacePool) {
        $script:RunspacePool.Close()
        $script:RunspacePool.Dispose()
        $script:RunspacePool = $null
    }
    
    Write-Log "SOCKS5 proxy stopped"
}

# Build GUI
$form = New-Object System.Windows.Forms.Form
$form.Text = "SOCKS5 Proxy Server"
$form.Size = New-Object System.Drawing.Size(500, 420)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Settings group
$grpSettings = New-Object System.Windows.Forms.GroupBox
$grpSettings.Text = "Settings"
$grpSettings.Location = New-Object System.Drawing.Point(10, 10)
$grpSettings.Size = New-Object System.Drawing.Size(465, 70)
$form.Controls.Add($grpSettings)

$lblBind = New-Object System.Windows.Forms.Label
$lblBind.Text = "Bind Address:"
$lblBind.Location = New-Object System.Drawing.Point(10, 28)
$lblBind.AutoSize = $true
$grpSettings.Controls.Add($lblBind)

$txtBind = New-Object System.Windows.Forms.TextBox
$txtBind.Text = "127.0.0.1"
$txtBind.Location = New-Object System.Drawing.Point(95, 25)
$txtBind.Size = New-Object System.Drawing.Size(100, 23)
$grpSettings.Controls.Add($txtBind)

$lblPort = New-Object System.Windows.Forms.Label
$lblPort.Text = "Port:"
$lblPort.Location = New-Object System.Drawing.Point(210, 28)
$lblPort.AutoSize = $true
$grpSettings.Controls.Add($lblPort)

$txtPort = New-Object System.Windows.Forms.NumericUpDown
$txtPort.Minimum = 1
$txtPort.Maximum = 65535
$txtPort.Value = 1080
$txtPort.Location = New-Object System.Drawing.Point(250, 25)
$txtPort.Size = New-Object System.Drawing.Size(70, 23)
$grpSettings.Controls.Add($txtPort)

$btnStart = New-Object System.Windows.Forms.Button
$btnStart.Text = "Start"
$btnStart.Location = New-Object System.Drawing.Point(340, 23)
$btnStart.Size = New-Object System.Drawing.Size(55, 28)
$grpSettings.Controls.Add($btnStart)

$btnStop = New-Object System.Windows.Forms.Button
$btnStop.Text = "Stop"
$btnStop.Location = New-Object System.Drawing.Point(400, 23)
$btnStop.Size = New-Object System.Drawing.Size(55, 28)
$btnStop.Enabled = $false
$grpSettings.Controls.Add($btnStop)

# Status
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = "Status: Stopped"
$lblStatus.Location = New-Object System.Drawing.Point(10, 88)
$lblStatus.Size = New-Object System.Drawing.Size(465, 20)
$lblStatus.ForeColor = [System.Drawing.Color]::DarkRed
$form.Controls.Add($lblStatus)

# Log group
$grpLog = New-Object System.Windows.Forms.GroupBox
$grpLog.Text = "Log"
$grpLog.Location = New-Object System.Drawing.Point(10, 110)
$grpLog.Size = New-Object System.Drawing.Size(465, 230)
$form.Controls.Add($grpLog)

$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Multiline = $true
$txtLog.ScrollBars = "Vertical"
$txtLog.ReadOnly = $true
$txtLog.Location = New-Object System.Drawing.Point(10, 20)
$txtLog.Size = New-Object System.Drawing.Size(445, 170)
$txtLog.Font = New-Object System.Drawing.Font("Consolas", 8.5)
$grpLog.Controls.Add($txtLog)

$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = "Clear Log"
$btnClear.Location = New-Object System.Drawing.Point(370, 195)
$btnClear.Size = New-Object System.Drawing.Size(85, 28)
$grpLog.Controls.Add($btnClear)

# Info label
$lblInfo = New-Object System.Windows.Forms.Label
$lblInfo.Text = "Configure your applications to use SOCKS5 proxy at the address above."
$lblInfo.Location = New-Object System.Drawing.Point(10, 350)
$lblInfo.Size = New-Object System.Drawing.Size(465, 20)
$lblInfo.ForeColor = [System.Drawing.Color]::DimGray
$form.Controls.Add($lblInfo)

# Timer for log updates
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 100
$timer.Add_Tick({
    while ($script:LogQueue.Count -gt 0) {
        $msg = $script:LogQueue.Dequeue()
        $txtLog.AppendText("$msg`r`n")
    }
})
$timer.Start()

# Event handlers
$btnStart.Add_Click({
    $port = [int]$txtPort.Value
    $bind = $txtBind.Text.Trim()
    
    if ([string]::IsNullOrWhiteSpace($bind)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a valid bind address.", "Error", "OK", "Error")
        return
    }
    
    if (Start-Socks5Proxy -Port $port -BindAddress $bind) {
        $btnStart.Enabled = $false
        $btnStop.Enabled = $true
        $txtBind.Enabled = $false
        $txtPort.Enabled = $false
        $lblStatus.Text = "Status: Running on ${bind}:${port}"
        $lblStatus.ForeColor = [System.Drawing.Color]::DarkGreen
    }
})

$btnStop.Add_Click({
    Stop-Socks5Proxy
    $btnStart.Enabled = $true
    $btnStop.Enabled = $false
    $txtBind.Enabled = $true
    $txtPort.Enabled = $true
    $lblStatus.Text = "Status: Stopped"
    $lblStatus.ForeColor = [System.Drawing.Color]::DarkRed
})

$btnClear.Add_Click({
    $txtLog.Clear()
})

$form.Add_FormClosing({
    $timer.Stop()
    Stop-Socks5Proxy
})

# Run
[void]$form.ShowDialog()
