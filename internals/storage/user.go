package storage

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id          int    `json:"id"`
	Email       string `json:"email"`
	IsChirpyRed bool   `json:"is_chirpy_red"`
}

type UserWithPassword struct {
	Password string `json:"password"`
	User
}

func (db *DB) CreateUser(email string, password string) (User, error) {
	_, ok := db.db.Users[email]

	if ok {
		return User{}, errors.New("user already exists")
	}

	id := len(db.db.Users) + 1

	defer db.writeDB(DBStruct{Users: make(map[string]UserWithPassword)})

	hash, _ := bcrypt.GenerateFromPassword([]byte(password), 10)

	newUser := UserWithPassword{
		User: User{
			Id:          id,
			Email:       email,
			IsChirpyRed: false,
		},
		Password: string(hash),
	}

	db.db.Users[fmt.Sprintf("%s", newUser.Email)] = newUser
	return newUser.User, nil
}

func (db *DB) GetUsers() ([]User, error) {
	userSlc := []UserWithPassword{}
	for id := range db.db.Users {
		userSlc = append(userSlc, db.db.Users[id])
	}

	basicUsers := []User{}

	for _, user := range userSlc {
		basicUsers = append(basicUsers, User{
			Id:    user.Id,
			Email: user.Email,
		})
	}

	return basicUsers, nil
}

//func (db *DB) GetUser(id int) (User, error) {
//	user, ok := db.db.Users[string(id)]
//
//	if !ok {
//		return User{}, errors.New("chirp not found")
//	}
//
//	return User{
//		Id:    user.Id,
//		Email: user.Email,
//	}, nil
//}

func (db *DB) GetUser(email, password string) (User, error) {
	user, ok := db.db.Users[email]

	if !ok {
		return User{}, errors.New("user not found")
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))

	if err != nil {
		return User{}, errors.New("email or password might be wrong")
	}

	return User{
		Id:          user.Id,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}, nil
}

func (db *DB) UpgradeUser(id int) error {
	users, _ := db.GetUsers()

	for _, user := range users {
		if user.Id == id {
			userToUpdate := db.db.Users[user.Email]

			userToUpdate.IsChirpyRed = true

			db.db.Users[user.Email] = userToUpdate
			return nil
		}
	}

	return errors.New("user not found")
}

// Todo: updateData could be a struct or map?
func (db *DB) UpdateUser(currentEmail, email, password string) (User, error) {
	user, ok := db.db.Users[currentEmail]

	if !ok {
		return User{}, errors.New("chirp not found")
	}

	delete(db.db.Users, currentEmail)

	hash, _ := bcrypt.GenerateFromPassword([]byte(password), 10)

	updatedUser := UserWithPassword{
		User: User{
			Id:    user.Id,
			Email: email,
		},
		Password: string(hash),
	}

	db.db.Users[email] = updatedUser

	return User{
		Id:    updatedUser.Id,
		Email: updatedUser.Email,
	}, nil
}
