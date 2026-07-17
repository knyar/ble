package bond

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/rigado/ble"
	"github.com/rigado/ble/linux/hci"
)

type manager struct {
	filePath string
	// lock is held exclusively by all public methods: even logically
	// read-only operations may quarantine a corrupt bond file, and Find
	// deletes invalid entries.
	lock sync.Mutex
	ble.Logger
}

type bondData struct {
	LongTermKey           string `json:"longTermKey"`
	EncryptionDiversifier string `json:"encryptionDiversifier"`
	RandomValue           string `json:"randomValue"`
	Legacy                bool   `json:"legacy"`
}

const (
	defaultBondFilename = "bonds.json"
)

func NewBondManager(bondFilePath string) hci.BondManager {
	if len(bondFilePath) == 0 {
		bondFilePath = defaultBondFilename
	}
	return &manager{
		filePath: bondFilePath,
		Logger:   ble.GetLogger(),
	}
}

//todo: is this function really needed?
func (m *manager) Exists(addr string) bool {
	if len(addr) != 12 {
		return false
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	bonds, err := m.loadBonds()
	if err != nil {
		m.Error(err)
		return false
	}

	for k := range bonds {
		if k == addr {
			return true
		}
	}

	return false
}

func (m *manager) Find(addr string) (hci.BondInfo, error) {
	if len(addr) != 12 {
		return nil, fmt.Errorf("invalid address")
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	bonds, err := m.loadBonds()
	if err != nil {
		return nil, err
	}

	bd, ok := bonds[addr]
	if !ok {
		return nil, fmt.Errorf("bond information not found for %s", addr)
	}

	//validate bondData information; if any of it is invalid, delete the bondData
	bi, bondErr := createBondInfo(bd)
	if bondErr != nil {
		delete(bonds, addr)
		err := m.storeBonds(bonds)
		if err != nil {
			m.Errorf("bondManager: store %s", err)
		}
		return nil, fmt.Errorf("found invalid bondData information: %v", bondErr)
	}

	return bi, nil
}

func (m *manager) Save(addr string, bond hci.BondInfo) error {
	if len(addr) != 12 {
		return fmt.Errorf("invalid address: %s", addr)
	}

	if bond == nil {
		return fmt.Errorf("empty bondData information")
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	bonds, err := m.loadBonds()
	if err != nil {
		return err
	}

	bd := createBondData(bond)

	//check to see if this address already exists
	if _, ok := bonds[addr]; ok {
		m.Infof("bondManager: replacing existing bond for %s", addr)
	}

	bonds[addr] = bd

	return m.storeBonds(bonds)
}

func (m *manager) Delete(addr string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	bonds, err := m.loadBonds()
	if err != nil {
		return err
	}

	if _, ok := bonds[addr]; ok {
		delete(bonds, addr)
	} else {
		return fmt.Errorf("bond for mac %v not found", addr)
	}

	err = m.storeBonds(bonds)
	if err != nil {
		return err
	}

	return nil
}

//this is mutex protected at the public function level
func (m *manager) loadBonds() (map[string]bondData, error) {
	fileData, err := os.ReadFile(m.filePath)
	if os.IsNotExist(err) {
		// A missing file simply means no bonds have been saved yet; it is
		// created on the first store rather than as a side effect of a read.
		return make(map[string]bondData), nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read bondData file information: %s", err)
	}

	var bonds map[string]bondData
	if len(fileData) > 0 {
		err = json.Unmarshal(fileData, &bonds)
		if err != nil {
			// The file is unreadable (e.g. truncated by a crash mid-write).
			// Quarantine it and start fresh: leaving it in place would make
			// every future load - and therefore every Save - fail, with no
			// way to ever bond again.
			quarantine := m.filePath + ".corrupt"
			if renameErr := os.Rename(m.filePath, quarantine); renameErr != nil {
				return nil, fmt.Errorf("failed to unmarshal current bondData info: %s", err)
			}
			m.Errorf("bondManager: bond file was corrupt (%s); moved to %s", err, quarantine)
			return make(map[string]bondData), nil
		}
	}

	if len(bonds) == 0 {
		bonds = make(map[string]bondData)
	}

	return bonds, nil
}

//this is mutex protected at the public function level.
//the file is replaced atomically (write to a temp file, fsync, rename) so
//that a crash or power loss mid-write cannot truncate existing bonds.
func (m *manager) storeBonds(bonds map[string]bondData) error {
	out, err := json.Marshal(bonds)
	if err != nil {
		return fmt.Errorf("failed to marshal bonds to json: %s", err)
	}

	dir, base := filepath.Split(m.filePath)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, base+".tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary bondData file: %s", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename

	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write bondData information: %s", err)
	}
	if err := tmp.Chmod(0644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to chmod bondData file: %s", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to sync bondData file: %s", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close bondData file: %s", err)
	}

	if err := os.Rename(tmp.Name(), m.filePath); err != nil {
		return fmt.Errorf("failed to update bondData information: %s", err)
	}

	// Best effort: persist the rename itself so the new file survives a
	// power loss. Not all filesystems support syncing directories.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	return nil
}

//bondData is a local structure
func createBondData(bi hci.BondInfo) bondData {
	b := bondData{}

	b.LongTermKey = hex.EncodeToString(bi.LongTermKey())

	eDiv := make([]byte, 2)
	binary.LittleEndian.PutUint16(eDiv, bi.EDiv())

	randVal := make([]byte, 8)
	binary.LittleEndian.PutUint64(randVal, bi.Random())

	b.EncryptionDiversifier = hex.EncodeToString(eDiv)
	b.RandomValue = hex.EncodeToString(randVal)
	b.Legacy = bi.Legacy()

	return b
}

//BondInfo is defined in the HCI packaged an used internally to enable
//encryption after a connect has been established with a device
func createBondInfo(b bondData) (hci.BondInfo, error) {
	ltk, err := hex.DecodeString(b.LongTermKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode long term key: %s", err)
	}
	if len(ltk) == 0 {
		return nil, fmt.Errorf("invalid long term key length")
	}

	eDiv, err := hex.DecodeString(b.EncryptionDiversifier)
	if err != nil {
		return nil, fmt.Errorf("invalid ediv in bondData file")
	}

	randVal, err := hex.DecodeString(b.RandomValue)
	if err != nil {
		return nil, fmt.Errorf("invalid random value in bondData file")
	}

	bi := hci.NewBondInfo(ltk, binary.LittleEndian.Uint16(eDiv), binary.LittleEndian.Uint64(randVal), b.Legacy)
	return bi, nil
}
