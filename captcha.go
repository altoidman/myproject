package main

import (
	"bytes"
	"log"
	"time"

	"github.com/dchest/captcha"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/gofiber/storage/memory"
	"github.com/gofiber/template/html/v2"
)

func main() {
	engine := html.New("./views", ".html")

	app := fiber.New(fiber.Config{
		Views: engine,
	})

	storage := memory.New(memory.Config{
		GCInterval: 10 * time.Minute,
	})

	store := session.New(session.Config{
		Storage:      storage,
		Expiration:   5 * time.Minute,
		KeyLookup:    "cookie:captcha_id",
		KeyGenerator: utils.UUIDv4,
		CookieHTTPOnly: true,
		CookieSameSite: "Lax",
	})

	app.Get("/", func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			log.Println("Error getting session:", err)
			return c.Status(500).SendString("Internal Server Error")
		}

		if sess.Get("captcha_id") == nil {
			captchaID := captcha.New()
			sess.Set("captcha_id", captchaID)
			if err := sess.Save(); err != nil {
				log.Println("Error saving session:", err)
				return c.Status(500).SendString("Internal Server Error")
			}
		}

		return c.Render("index", fiber.Map{
			"CaptchaID": sess.Get("captcha_id"),
			"Error":     c.Query("error"),
		})
	})

	app.Get("/captcha", func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			return c.Status(500).SendString("Internal Server Error")
		}

		captchaID, ok := sess.Get("captcha_id").(string)
		if !ok || captchaID == "" {
			return c.Status(404).SendString("CAPTCHA not found")
		}

		var content bytes.Buffer
		err = captcha.WriteImage(&content, captchaID, 200, 74)
		if err != nil {
			return c.Status(500).SendString("Failed to generate CAPTCHA")
		}

		c.Set("Content-Type", "image/png")
		return c.Send(content.Bytes())
	})

	app.Post("/verify", func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			return c.Status(500).SendString("Internal Server Error")
		}

		captchaID, ok := sess.Get("captcha_id").(string)
		if !ok {
			return c.Redirect("/?error=CAPTCHA+expired")
		}

		captchaSolution := c.FormValue("captcha_solution")
		if captchaSolution == "" {
			return c.Redirect("/?error=Please+enter+CAPTCHA")
		}

		if !captcha.VerifyString(captchaID, captchaSolution) {
			sess.Destroy()
			return c.Redirect("/?error=Invalid+CAPTCHA")
		}

		sess.Destroy()
		return c.SendString("CAPTCHA verification succeeded!")
	})

	app.Listen(":8080")
}
