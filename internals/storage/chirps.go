package storage

import (
	"errors"
)

type Chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
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

func (db *DB) GetChirps() ([]Chirp, error) {
	chirpSlc := []Chirp{}
	for id := range db.db.Chirps {
		chirpSlc = append(chirpSlc, db.db.Chirps[id])
	}

	return chirpSlc, nil
}

func (db *DB) GetChirp(id int) (Chirp, error) {
	chirp, ok := db.db.Chirps[id]

	if !ok {
		return Chirp{}, errors.New("chirp not found")
	}

	return chirp, nil
}
