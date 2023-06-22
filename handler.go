package main

import (
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
)

const (
	httpAddr = "127.0.0.1:8080"
)

func main() {
	// read DB into the memory
	if err := readDb(); err != nil {
		log.Fatalln(err)
	}
	http.HandleFunc("/register", Register)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/token", Token)
	if err := http.ListenAndServe(httpAddr, nil); err != nil {
		log.Fatalln(err)
	}
}

type resp struct {
	Ok  bool   `json:"ok"`
	Msg string `json:"msg"`
}

type tokenReqResp struct {
	resp
	Token string `json:"token"`
}

func Register(w http.ResponseWriter, r *http.Request) {
	var u user
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		response(w, resp{
			Ok:  false,
			Msg: err.Error(),
		}, http.StatusBadRequest)
		return
	}
	maxId, _, err := findByUsername(u.Username)
	if err != ErrUserNotFound {
		response(w, resp{
			Ok:  false,
			Msg: "user already exists",
		}, http.StatusBadRequest)
		return
	}
	u.Id = maxId + 1
	if err := addUser(u); err != nil {
		response(w, resp{
			Ok:  false,
			Msg: err.Error(),
		}, http.StatusBadRequest)
		return
	}
	claims := &MyCustomClaims{
		Id: u.Id,
	}
	token, err := genToken(claims)
	if err != nil {
		response(w, resp{
			Ok:  false,
			Msg: err.Error(),
		}, http.StatusBadRequest)
		return
	}
	response(w, tokenReqResp{
		Token: token,
		resp: resp{
			Ok:  true,
			Msg: "ok",
		},
	}, http.StatusOK)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var u user
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		response(w, resp{
			Ok:  false,
			Msg: err.Error(),
		}, http.StatusBadRequest)
		return
	}
	_, foundUser, err := findByUsername(u.Username)
	if err != nil {
		response(w, resp{
			Ok:  false,
			Msg: err.Error(),
		}, http.StatusBadRequest)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(u.Password)); errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		response(w, resp{
			Ok:  false,
			Msg: "wrong password",
		}, http.StatusOK)
		return
	}
	claims := &MyCustomClaims{
		Id: foundUser.Id,
	}
	token, err := genToken(claims)
	if err != nil {
		response(w, resp{
			Ok:  false,
			Msg: err.Error(),
		}, http.StatusBadRequest)
		return
	}
	response(w, tokenReqResp{
		Token: token,
		resp: resp{
			Ok:  true,
			Msg: "ok",
		},
	}, http.StatusOK)
}

func Token(w http.ResponseWriter, r *http.Request) {
	var t tokenReqResp
	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		response(w, resp{
			Ok:  false,
			Msg: err.Error(),
		}, http.StatusBadRequest)
		return
	}
	_, err = parseToken(t.Token)
	if err != nil {
		response(w, resp{
			Ok:  false,
			Msg: err.Error(),
		}, http.StatusOK)
		return
	}
	response(w, resp{
		Ok:  true,
		Msg: "ok",
	}, http.StatusOK)
}

func response(w http.ResponseWriter, data any, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}
