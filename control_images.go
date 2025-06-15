package main

import (
	"path/filepath"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/google/uuid"
)

func main() {
	app := fiber.New(fiber.Config{Views: html.New("./views", ".html")})

	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("home", fiber.Map{})
	})
	app.Post("/", func(c *fiber.Ctx) error {
		image, err := c.FormFile("image")
		if err != nil {
			return c.Render("home", fiber.Map{"message": "image is not found??"})
		}
		ext := filepath.Ext(image.Filename)
		allowed := map[string]bool{
			".png":  true,
			".jpeg": true,
			".jpg":  true,
			".gif":  true,
		}
		if !allowed[ext] {
			return c.Render("home", fiber.Map{"message": "extension your image is not accepted reuse with this ext .png .jpeg .jpg .gif"})
		}
		if image.Size > 1<<20 { // 1<<20 = 1mb or 2<<20 = 2mb / like this
			return c.Render("home", fiber.Map{"message": "Large image size, only less than 1MB required."})
		}
		err = c.SaveFile(image, "./images/"+uuid.NewString()+ext)
		return c.Render("home", fiber.Map{"message": "Successfully upload image"})

	})

	app.Listen(":8080")

}
