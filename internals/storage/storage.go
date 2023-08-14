package storage

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

type DB struct {
	path string
	db   DBStruct
	mu   *sync.Mutex
}

type Chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
}

type User struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

type DBStruct struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

func NewDB(path string, dbg bool) (*DB, error) {
	newDB := DB{
		path: path,
		db: DBStruct{
			Chirps: make(map[int]Chirp),
			Users:  make(map[int]User),
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

func (db *DB) CreateChirp(body string) (Chirp, error) {
	id := len(db.db.Chirps) + 1

	defer db.writeDB(DBStruct{Chirps: make(map[int]Chirp)})

	newChirp := Chirp{
		Id:   id,
		Body: body,
	}

	db.db.Chirps[newChirp.Id] = newChirp
	return newChirp, nil
}

func (db *DB) CreateUser(email string) (User, error) {
	id := len(db.db.Users) + 1

	defer db.writeDB(DBStruct{Users: make(map[int]User)})

	newUser := User{
		Id:    id,
		Email: email,
	}

	db.db.Users[newUser.Id] = newUser
	return newUser, nil
}

func (db *DB) GetChirps() ([]Chirp, error) {
	chirpSlc := []Chirp{}
	for id := range db.db.Chirps {
		chirpSlc = append(chirpSlc, db.db.Chirps[id])
	}

	return chirpSlc, nil
}

func (db *DB) GetUsers() ([]User, error) {
	userSlc := []User{}
	for id := range db.db.Chirps {
		userSlc = append(userSlc, db.db.Users[id])
	}

	return userSlc, nil
}

func (db *DB) GetChirp(id int) (Chirp, error) {
	chirp, ok := db.db.Chirps[id]

	if !ok {
		return Chirp{}, errors.New("chirp not found")
	}

	return chirp, nil
}

func (db *DB) GetUser(id int) (User, error) {
	user, ok := db.db.Users[id]

	if !ok {
		return User{}, errors.New("chirp not found")
	}

	return user, nil
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
		Users:  make(map[int]User),
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
