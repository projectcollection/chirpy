package main

import (
    "testing"
)

func ChirpValidationWorks(t *testing.T){

    one := "hello kerfuffle"

    cleanOne := CleanChirp(one)

    if cleanOne != "hello ****" {
        t.Fatal("it don't work")
    }
}
