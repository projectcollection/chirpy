package main

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
    "github.com/projectcollection/chirpy/internals/storage"
	"log"
	"net/http"
    "sort"
)

type apiConfig struct {
	fileserverHits int
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits += 1
		next.ServeHTTP(w, r)
	})
}

func main() {
	const port = "8080"

	metrics := apiConfig{}

    db, err := storage.NewDB("./db.json")

    if err != nil {
        fmt.Println("error creating db")
    }

	r := chi.NewRouter()
	apiRouter := chi.NewRouter()
	adminRouter := chi.NewRouter()

	apiRouter.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(http.StatusText(http.StatusOK)))
	})

	apiRouter.Post("/chirps", func(w http.ResponseWriter, r *http.Request) {
		type chirp struct {
			Body string `json:"body"`
		}

		decoder := json.NewDecoder(r.Body)
		chirpData := chirp{}
		err := decoder.Decode(&chirpData)

		if err != nil {
			return
		}

		if len(chirpData.Body) > 140 {
			RespondWithError(w, http.StatusBadRequest, "Chirp is too long")
			return
		}

        newChirp, _:= db.CreateChirp(CleanChirp(chirpData.Body))

		RespondWithJson(w, http.StatusCreated, newChirp)
		return
	})

	apiRouter.Get("/chirps", func(w http.ResponseWriter, r *http.Request) {
		type chirp struct {
			Body string `json:"body"`
		}

        chirps, _ := db.GetChirps()

        sort.Slice(chirps, func(i, j int) bool {
            return chirps[i].Id < chirps[j].Id
        })

		RespondWithJson(w, http.StatusCreated, chirps)
		return
	})

	adminRouter.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`
        <html>

        <body>
            <h1>Welcome, Chirpy Admin</h1>
            <p>Chirpy has been visited %d times!</p>
        </body>

        </html>
        `, metrics.fileserverHits)))
	})

	r.Handle("/app/", http.StripPrefix("/app", metrics.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	r.Handle("/app*", http.StripPrefix("/app", metrics.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	r.Handle("/assets", http.FileServer(http.Dir("./assets/")))
	r.Mount("/api", apiRouter)
	r.Mount("/admin", adminRouter)

	corsMux := middlewareCors(r)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: corsMux,
	}
	log.Printf("Serving on port: %s\n", port)
	log.Fatal(server.ListenAndServe())
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
