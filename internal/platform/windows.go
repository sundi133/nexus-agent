//go:build windows

package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// WindowsPlatform implements Platform using Win32 APIs and the registry.
type WindowsPlatform struct{}

func newPlatform() Platform { return &WindowsPlatform{} }

func (p *WindowsPlatform) OS() string { return "windows" }

func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return v
}

func regInt(root registry.Key, path, name string) (uint64, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	return v, err
}

func (p *WindowsPlatform) DeviceInfo(ctx context.Context) (DeviceInfo, error) {
	host, _ := os.Hostname()
	const cv = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	product := regString(registry.LOCAL_MACHINE, cv, "ProductName")
	build := regString(registry.LOCAL_MACHINE, cv, "CurrentBuild")
	// Windows 11 still reports "Windows 10" in ProductName.
	if n, _ := strconv.Atoi(build); n >= 22000 {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1)
	}
	ver := strings.TrimSpace(product + " " + regString(registry.LOCAL_MACHINE, cv, "DisplayVersion"))
	info := DeviceInfo{
		Hostname:    host,
		OS:          p.OS(),
		OSVersion:   ver,
		Kernel:      build,
		Arch:        runtime.GOARCH,
		Model:       regString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemProductName"),
		ConsoleUser: p.ConsoleUser(ctx),
	}
	info.SerialNumber, _ = powershell(ctx, "(Get-CimInstance Win32_BIOS).SerialNumber")
	return info, nil
}

func (p *WindowsPlatform) HardwareID(ctx context.Context) (string, error) {
	if id := regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, "MachineGuid"); id != "" {
		return id, nil
	}
	return "", errors.New("MachineGuid not found")
}

func (p *WindowsPlatform) ConsoleUser(ctx context.Context) string {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF {
		return ""
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		// Not running as SYSTEM (e.g. interactive debugging); fall back.
		out, _ := powershell(ctx, "(Get-CimInstance Win32_ComputerSystem).UserName")
		return out
	}
	defer tok.Close()
	return tokenUser(tok)
}

func tokenUser(tok windows.Token) string {
	tu, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	account, domain, _, err := tu.User.Sid.LookupAccount("")
	if err != nil {
		return tu.User.Sid.String()
	}
	return domain + `\` + account
}

func (p *WindowsPlatform) UserHomeDirs() []string {
	root := filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")
	return listHomeDirs(root, "Public", "Default", "Default User", "All Users", "defaultuser0")
}

func (p *WindowsPlatform) Processes(ctx context.Context) ([]Process, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	users := map[string]string{}
	var procs []Process
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		proc := Process{
			PID:  int(pe.ProcessID),
			PPID: int(pe.ParentProcessID),
			Name: windows.UTF16ToString(pe.ExeFile[:]),
		}
		proc.Path, proc.User = processDetails(pe.ProcessID, users)
		procs = append(procs, proc)
	}
	return procs, nil
}

// processDetails returns the image path and owning user (best effort;
// protected processes deny access even to SYSTEM).
func processDetails(pid uint32, users map[string]string) (string, string) {
	if pid == 0 || pid == 4 {
		return "", "SYSTEM"
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", ""
	}
	defer windows.CloseHandle(h)

	var path string
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err == nil {
		path = windows.UTF16ToString(buf[:n])
	}

	var owner string
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err == nil {
		if tu, err := tok.GetTokenUser(); err == nil {
			sid := tu.User.Sid.String()
			if name, ok := users[sid]; ok {
				owner = name
			} else {
				owner = tokenUser(tok)
				users[sid] = owner
			}
		}
		tok.Close()
	}
	return path, owner
}

func (p *WindowsPlatform) NetworkConnections(ctx context.Context) ([]Connection, error) {
	out, err := run(ctx, "netstat", "-ano")
	if err != nil {
		return nil, err
	}
	conns := parseWindowsNetstat(out)
	procs, _ := p.Processes(ctx)
	attachProcessNames(conns, procs)
	return conns, nil
}

const uninstallPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

func (p *WindowsPlatform) InstalledApps(ctx context.Context) ([]Application, error) {
	var apps []Application
	seen := map[string]bool{}
	add := func(root registry.Key, path string, access uint32) {
		for _, a := range readUninstallKey(root, path, access) {
			key := strings.ToLower(a.Name + "|" + a.Version)
			if !seen[key] {
				seen[key] = true
				apps = append(apps, a)
			}
		}
	}
	add(registry.LOCAL_MACHINE, uninstallPath, registry.WOW64_64KEY)
	add(registry.LOCAL_MACHINE, uninstallPath, registry.WOW64_32KEY)

	// Per-user installs (e.g. Cursor, Claude, VS Code user setup) live under
	// each loaded user hive in HKEY_USERS.
	if k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS); err == nil {
		sids, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, sid := range sids {
			if strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasSuffix(sid, "_Classes") {
				add(registry.USERS, sid+`\`+uninstallPath, 0)
			}
		}
	}
	return apps, nil
}

func readUninstallKey(root registry.Key, path string, access uint32) []Application {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|access)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var apps []Application
	for _, n := range names {
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE|access)
		if err != nil {
			continue
		}
		name, _, _ := sk.GetStringValue("DisplayName")
		if sys, _, err := sk.GetIntegerValue("SystemComponent"); name == "" || (err == nil && sys == 1) {
			sk.Close()
			continue
		}
		ver, _, _ := sk.GetStringValue("DisplayVersion")
		pub, _, _ := sk.GetStringValue("Publisher")
		loc, _, _ := sk.GetStringValue("InstallLocation")
		sk.Close()
		apps = append(apps, Application{Name: name, Version: ver, Publisher: pub, Path: loc, Source: "registry"})
	}
	return apps
}

func (p *WindowsPlatform) SecurityPosture(ctx context.Context) (*Posture, error) {
	checks := []PostureCheck{}

	out, err := run(ctx, "netsh", "advfirewall", "show", "allprofiles", "state")
	on, total := parseNetshFirewall(out)
	checks = append(checks, boolCheck(CheckFirewall, total > 0 && on == total, err, fmt.Sprintf("%d/%d profiles on", on, total)))

	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	out, err = run(ctx, "manage-bde", "-status", drive)
	checks = append(checks, boolCheck(CheckDiskEncryption, strings.Contains(out, "Protection On"), err, "BitLocker "+drive))

	out, err = powershell(ctx, "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json -Compress")
	var mp struct {
		AntivirusEnabled          bool
		RealTimeProtectionEnabled bool
	}
	if err == nil {
		err = json.Unmarshal([]byte(out), &mp)
	}
	checks = append(checks, boolCheck(CheckAntivirus, mp.AntivirusEnabled && mp.RealTimeProtectionEnabled, err, "Microsoft Defender"))

	lua, err := regInt(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA")
	checks = append(checks, boolCheck(CheckOSProtection, lua == 1, err, "UAC"))

	return &Posture{CollectedAt: time.Now().UTC(), Checks: checks}, nil
}

func (p *WindowsPlatform) LockScreen(ctx context.Context) error {
	// LockWorkStation only works from the interactive session; a service in
	// session 0 disconnects the console session instead, which locks it.
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF {
		return errors.New("no active console session")
	}
	_, err := run(ctx, "tsdiscon", strconv.FormatUint(uint64(session), 10))
	return err
}

func (p *WindowsPlatform) Notify(ctx context.Context, title, message string) error {
	_, err := run(ctx, "msg", "*", "/TIME:120", title+": "+message)
	return err
}

func powershell(ctx context.Context, script string) (string, error) {
	return run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}
