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
	polkaApiKey    string
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
		jwtSecret:   os.Getenv("JWT_SECRET"),
		polkaApiKey: os.Getenv("POLKA_API_KEY"),
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

		authHeader := r.Header.Get("Authorization")
		jwtToken := strings.Split(authHeader, " ")[1]

		token, err := jwt.ParseWithClaims(jwtToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.jwtSecret), nil
		})

		if err != nil {
			RespondWithError(w, 401, "unauthorized")
			return
		}

		subject, err := token.Claims.GetSubject()
		//now := jwt.NewNumericDate(time.Now())

		decoder := json.NewDecoder(r.Body)
		chirpData := chirp{}
		err = decoder.Decode(&chirpData)

		if err != nil {
			return
		}

		if len(chirpData.Body) > 140 {
			RespondWithError(w, http.StatusBadRequest, "Chirp is too long")
			return
		}
		authorId, _ := strconv.Atoi(strings.Split(subject, "")[0])

		newChirp, _ := db.CreateChirp(CleanChirp(chirpData.Body), authorId)

		RespondWithJson(w, http.StatusCreated, newChirp)
		return
	})

	apiRouter.Get("/chirps", func(w http.ResponseWriter, r *http.Request) {
		author_id := r.URL.Query().Get("author_id")
		sortOpt := r.URL.Query().Get("sort")

		chirps, _ := db.GetChirps()

		if len(author_id) > 0 {
			filteredChirps := []storage.Chirp{}
			for _, chirp := range chirps {
                id, _ := strconv.Atoi(author_id)
				if chirp.AuthorId == id {
					filteredChirps = append(filteredChirps, chirp)
				}
			}

            chirps = filteredChirps
		}

		sort.Slice(chirps, func(i, j int) bool {
            if len(sortOpt) == 0 || sortOpt == "asc" {
                return chirps[i].Id < chirps[j].Id
            }
            return chirps[i].Id > chirps[j].Id
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

	apiRouter.Delete("/chirps/{chirpid}", func(w http.ResponseWriter, r *http.Request) {
		chirpID := chi.URLParam(r, "chirpid")
		chirpIdInt, _ := strconv.Atoi(chirpID)

		authHeader := r.Header.Get("Authorization")
		jwtToken := strings.Split(authHeader, " ")[1]

		token, err := jwt.ParseWithClaims(jwtToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.jwtSecret), nil
		})

		if err != nil {
			RespondWithError(w, 401, "unauthorized")
			return
		}

		subject, err := token.Claims.GetSubject()
		authorId, _ := strconv.Atoi(strings.Split(subject, "")[0])

		chirp, _ := db.GetChirp(chirpIdInt)

		if authorId != chirp.AuthorId {
			RespondWithError(w, 403, "who u")
			return
		}

		db.DeleteChirp(chirpIdInt)

		RespondWithJson(w, http.StatusOK, struct{}{})
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
			Id int `json:"id"`
			user
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
			IsChirpyRed  bool   `json:"is_chirpy_red"`
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

		accessTokenClaims := jwt.RegisteredClaims{
			Issuer:    "chirpy-access",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprintf("%d-%s", foundUser.Id, foundUser.Email),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		}

		refreshTokenClaims := jwt.RegisteredClaims{
			Issuer:    "chirpy-refresh",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprintf("%d-%s", foundUser.Id, foundUser.Email),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * 60 * time.Hour)),
		}

		accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
		refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)

		accessTokenString, _ := accessToken.SignedString([]byte(cfg.jwtSecret))
		refreshTokenString, _ := refreshToken.SignedString([]byte(cfg.jwtSecret))

		toReturn := userWithToken{
			Id: foundUser.Id,
			user: user{
				Email: foundUser.Email,
			},
			Token:        accessTokenString,
			RefreshToken: refreshTokenString,
			IsChirpyRed:  foundUser.IsChirpyRed,
		}

		RespondWithJson(w, http.StatusOK, toReturn)
		return
	})

	apiRouter.Put("/users", func(w http.ResponseWriter, r *http.Request) {
		type user struct {
			Id          int    `json:"id"`
			Email       string `json:"email"`
			Token       string `json:"token"`
			IsChirpyRed bool   `json:"is_chirpy_red"`
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
		issuer, err := token.Claims.GetIssuer()

		now := jwt.NewNumericDate(time.Now())

		if expTime != nil && now.After(expTime.Time) || issuer == "chirpy-refresh" {
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

		//Welp... this is unfortunate
		if updatedUser.Id == 0 {
			users, _ := db.GetUsers()

			id, _ := strconv.Atoi(strings.Split(subject, "-")[0])
			for _, user := range users {
				if user.Id == id {
					updatedUser = user
				}
			}
		}

		updatedUser, _ = db.UpdateUser(updatedUser.Email, updateData.Email, updateData.Password)

		accessTokenClaims := jwt.RegisteredClaims{
			Issuer:    "chirpy-access",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprintf("%d-%s", updatedUser.Id, updatedUser.Email),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		}

		token.Claims = accessTokenClaims

		newJwtToken, _ := token.SignedString([]byte(cfg.jwtSecret))

		userToReturn := user{
			Id:          updatedUser.Id,
			Email:       updatedUser.Email,
			Token:       newJwtToken,
			IsChirpyRed: updateData.IsChirpyRed,
		}

		RespondWithJson(w, http.StatusOK, userToReturn)
	})

	apiRouter.Post("/polka/webhooks", func(w http.ResponseWriter, r *http.Request) {
		type polkaEvent struct {
			Event string         `json:"event"`
			Data  map[string]int `json:"data"`
		}

		authHeader := r.Header.Get("Authorization")
		authArr := strings.Split(authHeader, " ")

		if len(authArr) < 2 || authArr[1] != cfg.polkaApiKey {
			RespondWithError(w, 401, "unauthorized")
			return
		}

		decoder := json.NewDecoder(r.Body)
		eventData := polkaEvent{}
		decoder.Decode(&eventData)

		if eventData.Event != "user.upgraded" {
			RespondWithJson(w, http.StatusOK, struct{}{})
			return
		}

		err := db.UpgradeUser(eventData.Data["user_id"])

		if err != nil {
			RespondWithError(w, 404, "not found")
			return
		}

		RespondWithJson(w, http.StatusOK, struct{}{})
		return
	})

	apiRouter.Post("/refresh", func(w http.ResponseWriter, r *http.Request) {
		type res struct {
			Token string `json:"token"`
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

		issuer, err := token.Claims.GetIssuer()
		subject, err := token.Claims.GetSubject()

		if issuer != "chirpy-refresh" || err != nil || db.IsRFTokenRevoked(jwtToken) {
			RespondWithError(w, 401, "unauthorized")
			return
		}

		accessTokenClaims := jwt.RegisteredClaims{
			Issuer:    "chirpy-access",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprintf("%s", subject),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		}

		newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)

		accessTokenString, _ := newAccessToken.SignedString([]byte(cfg.jwtSecret))

		RespondWithJson(w, http.StatusOK, res{
			Token: accessTokenString,
		})
	})

	apiRouter.Post("/revoke", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		resfreshToken := strings.Split(authHeader, " ")[1]

		db.RevokeRFToken(resfreshToken)

		RespondWithJson(w, http.StatusOK, struct{}{})
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
