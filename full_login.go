package main

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"log"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/storage/redis"
	"github.com/gofiber/template/html/v2"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

var store *session.Store

func main() {
	storage := redis.New(redis.Config{
		Host:     "127.0.0.1",
		Port:     6379,
		Password: "",
		Database: 0,
	})
	store = session.New(session.Config{
		Storage:        storage,
		KeyLookup:      "cookie:session_id",
		KeyGenerator:   func() string { return uuid.NewString() },
		CookieHTTPOnly: true,  // منع الوصول عبر JavaScript
		CookieSameSite: "Lax", // الحماية من CSRF
	})

	app := fiber.New(fiber.Config{
		Views: html.New("./views", ".html"),
	})

	app.Get("/", func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			log.Fatal(err)
		}
		name , ok := sess.Get("username").(string)
		if !ok {
			name = ""
		}
		return c.Render("login", fiber.Map{"session":name})
	})

	app.Post("/", func(c *fiber.Ctx) error {
		username := c.FormValue("username")
		pass := c.FormValue("password")
		sess, err := store.Get(c)
		if err != nil {
			log.Fatal(err)
		}
		defer sess.Save()

		db, err := sqlx.Connect("mysql", "root:root!@tcp(127.0.0.1:3306)/home")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		var user struct {
			Username string
			Password string
		}
		err = db.Get(&user, "SELECT username,password FROM users WHERE username = ?", username)
		if err != nil {
			return c.Render("login", fiber.Map{"msg": "username or password not right"})
		}
		if user.Password != pass {
			return c.Render("login", fiber.Map{"msg": "username or password not right!"})
		}
		sess.Set("username",username)
		sess.SetExpiry(100 * time.Second)
		return c.Render("login", fiber.Map{"seccuss": "seccuss for login!"})

	})

	app.Listen((":8080"))
}
