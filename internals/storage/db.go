package storage

import (
	"encoding/json"
	"os"
	"sync"
)

type DB struct {
	path string
	db   DBStruct
	mu   *sync.Mutex
}

type DBStruct struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[string]UserWithPassword `json:"users"`
}

func NewDB(path string, dbg bool) (*DB, error) {
	newDB := DB{
		path: path,
		db: DBStruct{
			Chirps: make(map[int]Chirp),
			Users:  make(map[string]UserWithPassword),
		},
		mu: &sync.Mutex{},
	}

	var err error

	if dbg {
		newDB.writeDB(newDB.db)
	} else {
		err = newDB.ensureDB()
	}

	if err != nil {
		return &DB{}, err
	}

	return &newDB, nil
}

func (db *DB) ensureDB() error {
	dbStruct, err := db.loadDB()

	b, err := json.Marshal(dbStruct)

	if err != nil {
		return err
	}

	err = os.WriteFile(db.path, b, 0666)

	if err != nil {
		return err
	}

	return nil
}

func (db *DB) loadDB() (DBStruct, error) {
	b, err := os.ReadFile(db.path)

	if err != nil {
		return DBStruct{}, err
	}

	dbStruct := DBStruct{
		Chirps: make(map[int]Chirp),
		Users:  make(map[string]UserWithPassword),
	}
	err = json.Unmarshal(b, &dbStruct)

	if err != nil {
		return DBStruct{}, err
	}

	db.db = dbStruct

	return dbStruct, err
}

func (db *DB) writeDB(dbStruct DBStruct) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for id := range dbStruct.Chirps {
		db.db.Chirps[id] = dbStruct.Chirps[id]
	}

	for id := range dbStruct.Users {
		db.db.Users[id] = dbStruct.Users[id]
	}

	b, err := json.Marshal(db.db)

	if err != nil {
		return err
	}

	err = os.WriteFile(db.path, b, 0666)

	if err != nil {
		return err
	}

	return err
}
