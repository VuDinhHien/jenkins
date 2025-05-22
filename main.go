package main

import (
	"fiber-auth-app/models"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/template/html/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var (
	db    *gorm.DB
	store *session.Store
)

func main() {
	// template
	engine := html.New("./views", ".html")

	app := fiber.New(fiber.Config{
		Views: engine,
	})

	app.Static("/", "./public")
	// Kết nối cơ sở dữ liệu MySQL
	dsn := "root@tcp(127.0.0.1:3306)/fiber_demo?charset=utf8mb4&parseTime=True&loc=Local"
	database, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Không thể kết nối cơ sở dữ liệu:", err)
	}
	db = database

	// Tự động tạo bảng
	db.AutoMigrate(&models.User{})

	// Khởi tạo session store
	store = session.New()

	// GET /login
	app.Get("/login", func(c *fiber.Ctx) error {
		return c.Render("pages/auth/login", fiber.Map{})
	})

	// POST /login
	app.Post("/login", func(c *fiber.Ctx) error {
		username := c.FormValue("username")
		password := c.FormValue("password")

		var user models.User
		result := db.Where("username = ?", username).First(&user)
		if result.Error != nil {
			return c.Redirect("/login")
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
			return c.Redirect("/login")
		}

		sess, err := store.Get(c)
		if err != nil {
			return err
		}
		sess.Set("username", username)
		sess.Save()

		return c.Redirect("/")
	})

	// GET /register
	app.Get("/register", func(c *fiber.Ctx) error {
		return c.Render("pages/auth/register", fiber.Map{})
	})

	// POST /register
	app.Post("/register", func(c *fiber.Ctx) error {
		username := c.FormValue("username")
		password := c.FormValue("password")
		confirmPassword := c.FormValue("confirm_password")

		// Kiểm tra mật khẩu và xác nhận mật khẩu
		if password != confirmPassword {
			return c.Render("register", fiber.Map{
				"Error": "Mật khẩu và xác nhận mật khẩu không khớp.",
			})
		}

		// Kiểm tra xem tên người dùng đã tồn tại chưa
		var existingUser models.User
		if err := db.Where("username = ?", username).First(&existingUser).Error; err == nil {
			return c.Render("register", fiber.Map{
				"Error": "Tên người dùng đã tồn tại.",
			})
		}

		// Mã hóa mật khẩu
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}

		user := models.User{
			Username: username,
			Password: string(hashedPassword),
		}

		result := db.Create(&user)
		if result.Error != nil {
			return c.Render("register", fiber.Map{
				"Error": "Đăng ký thất bại. Vui lòng thử lại.",
			})
		}

		return c.Redirect("/login")
	})

	// kiểm tra đăng nhập
	app.Use(func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			return err
		}
		if sess.Get("username") == nil && c.Path() != "pages/auth/login" && c.Path() != "pages/auth/register" {
			return c.Redirect("/login")
		}
		return c.Next()
	})

	// GET /
	app.Get("/", func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			return err
		}
		username := sess.Get("username")
		return c.Render("pages/auth/index", fiber.Map{
			"Username": username,
		})
	})

	// GET /logout
	app.Get("/logout", func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			return err
		}
		sess.Destroy()
		return c.Redirect("/login")
	})

	log.Fatal(app.Listen(":3000"))
}
