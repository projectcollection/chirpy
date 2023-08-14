package main

import (
	"strings"
    "slices"
)

var invalidWords = []string{"kerfuffle", "sharbert", "fornax"}

func CleanChirp(chirp string) string {
    words := strings.Split(chirp, " ")

    for i, word := range words {
        lowerWord := strings.ToLower(word)
        if slices.Contains(invalidWords, lowerWord) {
            words[i] = "****"
        }
    }

    return strings.Join(words, " ")
}
