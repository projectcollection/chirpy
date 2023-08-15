package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/projectcollection/chirpy/internals/storage"
)

type apiConfig struct {
	fileserverHits int
	jwtSecret      string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits += 1
		next.ServeHTTP(w, r)
	})
}

func main() {
	godotenv.Load()
	const port = "8080"

	dbg := flag.Bool("debug", false, "Enable debug mode.")
	flag.Parse()

	cfg := apiConfig{
		jwtSecret: os.Getenv("JWT_SECRET"),
	}
	db, err := storage.NewDB("./db.json", *dbg)

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

		newChirp, _ := db.CreateChirp(CleanChirp(chirpData.Body))

		RespondWithJson(w, http.StatusCreated, newChirp)
		return
	})

	apiRouter.Get("/chirps", func(w http.ResponseWriter, r *http.Request) {
		chirps, _ := db.GetChirps()
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].Id < chirps[j].Id
		})

		RespondWithJson(w, http.StatusOK, chirps)
		return
	})

	apiRouter.Get("/chirps/{chirpid}", func(w http.ResponseWriter, r *http.Request) {
		chirpID := chi.URLParam(r, "chirpid")

		id, err := strconv.Atoi(chirpID)
		chirp, err := db.GetChirp(id)

		if err != nil {
			RespondWithError(w, http.StatusNotFound, "not found")
		}

		RespondWithJson(w, http.StatusOK, chirp)
		return
	})

	apiRouter.Post("/users", func(w http.ResponseWriter, r *http.Request) {
		type user struct {
			Email   string `json:"email"`
			Passord string `json:"password"`
		}

		decoder := json.NewDecoder(r.Body)
		userData := user{}
		err := decoder.Decode(&userData)

		if err != nil {
			return
		}

		newUser, _ := db.CreateUser(userData.Email, userData.Passord)

		RespondWithJson(w, http.StatusCreated, newUser)
		return
	})

	apiRouter.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		type user struct {
			Email   string `json:"email"`
			Passord string `json:"password"`
			Exp     int    `json:"expires_in_seconds"`
		}

		type userWithToken struct {
			Id    int `json:"id"`
			User  user
			Token string `json:"token"`
		}

		decoder := json.NewDecoder(r.Body)
		userData := user{}
		err := decoder.Decode(&userData)

		if err != nil {
			return
		}

		foundUser, err := db.GetUser(userData.Email, userData.Passord)

		if err != nil {
			RespondWithError(w, 401, "wrong password")
			return
		}

		claims := jwt.RegisteredClaims{
			Issuer:   "chirpy",
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Subject:  fmt.Sprintf("%d-%s", foundUser.Id, foundUser.Email),
		}

		if userData.Exp > 0 {
			claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Duration(userData.Exp)))
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, _ := token.SignedString([]byte(cfg.jwtSecret))

		RespondWithJson(w, http.StatusOK, userWithToken{
			Id: foundUser.Id,
			User: user{
				Email: foundUser.Email,
			},
			Token: tokenString,
		})
		return
	})

	apiRouter.Put("/users", func(w http.ResponseWriter, r *http.Request) {
		type user struct {
			Id    int    `json:"id"`
			Email string `json:"email"`
			Token string `json:"token"`
		}

		type userWithPassword struct {
			user
			Password string `json:"password"`
		}

		authHeader := r.Header.Get("Authorization")
		jwtToken := strings.Split(authHeader, " ")[1]

		token, err := jwt.ParseWithClaims(jwtToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.jwtSecret), nil
		})

		if err != nil {
			RespondWithError(w, 401, "unauthorized")
			return
		}
		expTime, err := token.Claims.GetExpirationTime()

		if err != nil {
			fmt.Println("exptime", err)
		}

		now := jwt.NewNumericDate(time.Now())

		if expTime != nil && now.Before(expTime.Time) {
			RespondWithError(w, 401, "unauthorized")
			return
		}

		decoder := json.NewDecoder(r.Body)
		updateData := userWithPassword{}
		err = decoder.Decode(&updateData)

		if err != nil {
			return
		}

		subject, _ := token.Claims.GetSubject()
		updatedUser, _ := db.UpdateUser(strings.Split(subject, "-")[1], updateData.Email, updateData.Password)

		userToReturn := user{
			Id:    updatedUser.Id,
			Email: updatedUser.Email,
			Token: jwtToken,
		}

		RespondWithJson(w, http.StatusOK, userToReturn)
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
        `, cfg.fileserverHits)))
	})

	r.Handle("/app/", http.StripPrefix("/app", cfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	r.Handle("/app*", http.StripPrefix("/app", cfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
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
