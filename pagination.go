package main

import (
	"fmt"
	"log"
	"math"
	"strconv"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/jmoiron/sqlx"
)

func main() {

	app := fiber.New(fiber.Config{
		Views: html.New("./views", ".html"),
	})
	db, err := sqlx.Connect("mysql", "root:root!@tcp(127.0.0.1:3306)/home")
	if err != nil {
		log.Println(err)
	}
	defer db.Close()

	app.Get("/", func(c *fiber.Ctx) error {
		var users []struct {
			ID       int
			Username string
			Created  string
		}
		page, _ := strconv.Atoi(c.Query("page", "1"))
		if page < 1 {
			page = 1
		}
		limit := 1
		offset := (page - 1) * limit

		err = db.Select(&users, "SELECT id,username,created FROM users LIMIT ? OFFSET ?", limit, offset)
		if err != nil {
			log.Println(err)
		}

		var total int
		err = db.Get(&total, "SELECT COUNT(*) FROM users")

		totalPages := int(math.Ceil(float64(total) / float64(limit))) 
		result := fmt.Sprintf("/?page=%d",totalPages)
		if page > totalPages {
			return c.Redirect(result)
		}

		return c.Render("users", fiber.Map{
			"bodys": users,
			"all": fiber.Map{
				"pages": totalPages +1,
				"page":  page,
				"m":  page - 1,
				"p":  page + 1,
				"Prev": page>1,
				"Next":page<totalPages,
			},
		})

	})

	app.Listen(":8080")

}
