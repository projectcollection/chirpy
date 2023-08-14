package main

import (
	"encoding/json"
	"net/http"
)

type Err struct {
	Error string `json:"error"`
}

type Ok struct {
	CleanedBody string `json:"cleaned_body"`
}

func RespondWithError(w http.ResponseWriter, code int, msg string) {
	res, _ := json.Marshal(Err{
		Error: msg,
	})

	w.WriteHeader(code)
	w.Header().Add("Content-Type", "application/json")
	w.Write(res)
}

func RespondWithJson(w http.ResponseWriter, code int, payload interface{}) {
	res, _ := json.Marshal(payload)

	w.WriteHeader(code)
	w.Header().Add("Content-Type", "application/json")
	w.Write(res)
}
