package license

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

// HardwareSources lists the files the hardware fingerprint is built from.
// Inside Docker the host's files are mounted read-only under /host.
type HardwareSources struct {
	MachineIDPath   string // /etc/machine-id
	ProductUUIDPath string // /sys/class/dmi/id/product_uuid (absent on some VMs)
}

// HardwareID derives a stable 64-character fingerprint of this server. It is
// a hash, so it reveals nothing about the machine.
func HardwareID(src HardwareSources) (string, error) {
	machineID := readTrim(src.MachineIDPath)
	if machineID == "" {
		return "", errors.New("cannot read machine ID from " + src.MachineIDPath)
	}
	h := sha256.New()
	h.Write([]byte("isp-netcontrol-hwid-v1\x00"))
	h.Write([]byte(strings.ToLower(machineID)))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(readTrim(src.ProductUUIDPath))))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readTrim(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
