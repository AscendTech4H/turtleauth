package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/gorilla/securecookie"

	_ "github.com/go-sql-driver/mysql"

	"github.com/AscendTech4H/turtleauth"
)

// Credentials which stores google ids.
type Credentials struct {
	Cid     string `json:"client_id"`
	Csecret string `json:"client_secret"`
}

// User is a retrieved and authentiacted google user.
type User struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Profile       string `json:"profile"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Gender        string `json:"gender"`
}

var cred Credentials
var conf *oauth2.Config
var state string

func init() {

}

func main() {
	log.Println("Starting auth server. . . ")
	var dbs string
	var addr string
	var k string
	var credfile string
	var site string
	flag.StringVar(&dbs, "db", "/", "Database source string")
	flag.StringVar(&addr, "addr", ":9001", "Server port for authentication")
	flag.StringVar(&k, "key", ".authkey", "Key file")
	flag.StringVar(&credfile, "cred", ".cred", "Google oauth2 credentials file")
	flag.StringVar(&site, "site", "", "Domain name")
	flag.Parse()
	if site == "" {
		panic("site not specified")
	}
	log.Println("Loading keys. . . ")
	d, err := ioutil.ReadFile(k)
	if err != nil {
		panic(err)
	}
	var keys struct {
		HashKey  []byte
		BlockKey []byte
	}
	err = json.Unmarshal(d, &keys)
	if err != nil {
		panic(err)
	}
	sc := securecookie.New(keys.HashKey, keys.BlockKey)
	sc.SetSerializer(securecookie.GobEncoder{})
	log.Println("Loading oauth credentials. . . ")
	file, err := ioutil.ReadFile(credfile)
	if err != nil {
		log.Printf("File error: %v\n", err)
		os.Exit(1)
	}
	json.Unmarshal(file, &cred)
	fmt.Println(cred)

	conf = &oauth2.Config{
		ClientID:     cred.Cid,
		ClientSecret: cred.Csecret,
		RedirectURL:  fmt.Sprintf("https://auth.%s/auth", site),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email", // You have to select your own scope from here -> https://developers.google.com/identity/protocols/googlescopes#google_sign-in
		},
		Endpoint: google.Endpoint,
	}
	log.Println("Connecting to DB. . . ")
	db, err := sql.Open("mysql", dbs)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	log.Println("Connected")
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	})
	http.HandleFunc("/perm", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Incorrect request method", http.StatusMethodNotAllowed)
			return
		}
		var ac turtleauth.AuthCheck
		err := gob.NewDecoder(r.Body).Decode(&ac)
		if err != nil {
			http.Error(w, "Decode error", http.StatusInternalServerError)
			return
		}
		if !ac.P.Check() {
			http.Error(w, "Bad PermissionClass", http.StatusBadRequest)
			return
		}
		var uid int
		err = sc.Decode("turtleauth", ac.C.Value, &uid)
		if err != nil {
			http.Error(w, "Cookie error", http.StatusUnauthorized)
			return
		}
		res, err := db.Query(fmt.Sprintf("SELECT * FROM PERM_%s WHERE id=%d", ac.P.Name, uid))
		if err != nil {
			http.Error(w, "SQL Error", http.StatusInternalServerError)
			return
		}
		defer res.Close()
		if res.Next() {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Auth successful"))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Auth rejected"))
		}
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Incorrect request method", http.StatusMethodNotAllowed)
			return
		}
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Form parse error", http.StatusBadRequest)
			return
		}
		dest := r.FormValue("dest")
		if dest == "" {
			http.Error(w, "Missing destination", http.StatusBadRequest)
			return
		}
		expire := time.Now().Add(5 * time.Minute) //Delete cookie in 5 min
		http.SetCookie(w, &http.Cookie{
			Name:    "authdest",
			Value:   dest,
			Expires: expire,
		})
		key := make([]byte, 32)
		_, err = rand.Read(key)
		if err != nil {
			http.Error(w, "Random number generator failure", http.StatusInternalServerError)
			return
		}
		kstr := base64.StdEncoding.EncodeToString(key)
		cook := &http.Cookie{
			Name:    "state",
			Value:   kstr,
			Expires: expire,
		}
		http.SetCookie(w, cook)
		authaddr := conf.AuthCodeURL(kstr) + "&access_type=offline"
		http.Redirect(w, r, authaddr, http.StatusTemporaryRedirect)
	})
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Incorrect request method", http.StatusMethodNotAllowed)
			return
		}
		cook, err := r.Cookie("state")
		if err != nil {
			http.Error(w, "Error getting state cookie", http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:   "state",
			Value:  "",
			MaxAge: -1, //Delete now
		})
		dest, err := r.Cookie("authdest")
		if err != nil {
			http.Error(w, "Error retrieving authdest cookie", http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:   "authdest",
			Value:  "",
			MaxAge: -1, //Delete now
		})
		if r.URL.Query().Get("state") != cook.Value {
			http.Error(w, "Unmatched state", http.StatusUnauthorized)
			log.Println(r.URL.Query().Get("state"), cook.Value)
			return
		}
		tok, err := conf.Exchange(oauth2.NoContext, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Exchange error", http.StatusUnauthorized)
			log.Printf("Exchange error: %s\n", err.Error())
		}
		client := conf.Client(oauth2.NoContext, tok)
		lookup, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
		if err != nil {
			http.Error(w, "User info request error", http.StatusUnauthorized)
			log.Println(err)
			return
		}
		defer lookup.Body.Close()
		var uinfo User
		err = json.NewDecoder(lookup.Body).Decode(&uinfo)
		if err != nil {
			http.Error(w, "User info request decode error", http.StatusInternalServerError)
			log.Println(err)
			return
		}
		res, err := db.Query("SELECT id FROM users WHERE email=?", uinfo.Email)
		if err != nil {
			http.Error(w, "Database errror", http.StatusInternalServerError)
			log.Printf("Database error: %s\n", err.Error())
			return
		}
		var id int
		if !res.Next() {
			_, err = db.Exec("INSERT INTO users (email) VALUES (?)", uinfo.Email)
			if err != nil {
				http.Error(w, "Database errror", http.StatusInternalServerError)
				log.Printf("Database error: %s\n", err.Error())
				return
			}
			res, err = db.Query("SELECT id FROM users WHERE email=?", uinfo.Email)
			if err != nil {
				http.Error(w, "Database errror", http.StatusInternalServerError)
				log.Printf("Database error: %s\n", err.Error())
				return
			}
			if !res.Next() {
				http.Error(w, "This shouldnt happen", http.StatusInternalServerError)
			}
		}
		err = res.Scan(&id)
		if err != nil {
			http.Error(w, "Database errror", http.StatusInternalServerError)
			log.Printf("Database error: %s\n", err.Error())
			return
		}
		cstr, err := sc.Encode("turtleauth", &id)
		if err != nil {
			http.Error(w, "Cookie encryption error", http.StatusInternalServerError)
			log.Printf("Cookie encryption error: %s\n", err.Error())
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:   "turtleauth",
			Domain: site,
			Value:  cstr,
		})
		//All good - redirect
		http.Redirect(w, r, dest.Value, http.StatusMovedPermanently)
	})
	log.Println("Starting http server")
	panic(http.ListenAndServe(addr, nil))
}
