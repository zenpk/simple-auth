package main

import (
	"encoding/json"
	"errors"
	"github.com/zenpk/go-mod-path"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"os"
)

const (
	BcryptCost = 12
	FileName   = "db.json"
	Permission = 0600
)

var (
	ErrUserNotFound = errors.New("user not found")
)

type userDb struct {
	Users []user `json:"users"`
}

type user struct {
	Id       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var db userDb

func readDb() error {
	path, err := gmp.GetNearestPath()
	if err != nil {
		return err
	}
	jsonFile, err := os.Open(path + FileName)
	if err != nil {
		return err
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			log.Fatalln(err)
		}
	}()
	byteValue, _ := io.ReadAll(jsonFile)
	if err := json.Unmarshal(byteValue, &db); err != nil {
		return err
	}
	return nil
}

// findByUsername if found, return the user's id, else, return the maximum id
func findByUsername(username string) (uint64, user, error) {
	maxId := uint64(0)
	for _, u := range db.Users {
		if u.Id > maxId {
			maxId = u.Id
		}
		if u.Username == username {
			return u.Id, u, nil
		}
	}
	return maxId, user{}, ErrUserNotFound
}

func addUser(user user) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), BcryptCost)
	if err != nil {
		return err
	}
	user.Password = string(passwordHash)
	db.Users = append(db.Users, user)
	jsonData, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	path, err := gmp.GetNearestPath()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+FileName, jsonData, Permission); err != nil {
		return err
	}
	return nil
}
