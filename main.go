package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3" // SQLiteドライバ
	"golang.org/x/crypto/bcrypt"
	//_ "modernc.org/sqlite"
)

// User represents a user of the application
type User struct {
	Username     string
	PasswordHash []byte
}

var (
	users = make(map[string]User) // In-memory user storage
	lock  = sync.Mutex{}
)

// Day represents a single day in the calendar
type Day struct {
	Date     int
	Empty    bool
	Today    bool
	Schedule string
}

// Week represents a week in the calendar
type Week struct {
	Days []Day
}

// CalendarData represents the data passed to the calendar template
type CalendarData struct {
	Year  int
	Month string
	Weeks []Week
	Prev  string
	Next  string
}

// Schedule represents a single day's schedule
type Schedule struct {
	Date    string `json:"date"`
	Content string `json:"content"`
}

var (
	scheduleMap = make(map[string]string) // In-memory storage for schedules
	mutex       = &sync.Mutex{}           // For thread-safe access to the map
)

/*func calendarHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	firstOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	weekday := int(firstOfMonth.Weekday())

	// Get the number of days in the month
	daysInMonth := 32 - firstOfMonth.AddDate(0, 0, -32).Day()

	// Build weeks and days
	var weeks []Week
	var days []Day
	for i := 0; i < weekday; i++ {
		days = append(days, Day{}) // Empty days before the start of the month
	}
	for day := 1; day <= daysInMonth; day++ {
		isToday := now.Day() == day && now.Month() == firstOfMonth.Month() && now.Year() == firstOfMonth.Year()
		days = append(days, Day{Date: day, Today: isToday})
		if len(days) == 7 {
			weeks = append(weeks, Week{Days: days})
			days = []Day{}
		}
	}
	if len(days) > 0 {
		for len(days) < 7 {
			days = append(days, Day{}) // Empty days after the end of the month
		}
		weeks = append(weeks, Week{Days: days})
	}

	data := CalendarData{
		Year:  now.Year(),
		Month: now.Month().String(),
		Weeks: weeks,
	}

	tmpl := template.Must(template.ParseFiles("templates/calendar.html"))
	tmpl.Execute(w, data)
}*/

func setupDatabase() *sql.DB {
	// SQLite データベースに接続
	db, err := sql.Open("sqlite3", "./calendar.db")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// ユーザー情報を保存するテーブルを作成
	createUsersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL
	);
	`
	_, err = db.Exec(createUsersTable)
	if err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}

	// スケジュール情報を保存するテーブルを作成
	createSchedulesTable := `
	CREATE TABLE IF NOT EXISTS schedules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		date TEXT NOT NULL,
		content TEXT NOT NULL
	);
	`
	_, err = db.Exec(createSchedulesTable)
	if err != nil {
		log.Fatalf("Failed to create schedules table: %v", err)
	}

	return db
}

func main() {
	// SQLiteデータベースのセットアップ
	setupDatabase()

	// Gorilla Muxルーターの設定
	r := mux.NewRouter()

	// ルートの設定
	r.HandleFunc("/", homeHandler).Methods("GET")
	r.HandleFunc("/register", registerHandler).Methods("GET", "POST")
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/calendar", calendarHandler).Methods("GET")
	r.HandleFunc("/save", saveScheduleHandler).Methods("POST")     // スケジュール保存
	r.HandleFunc("/get", getScheduleHandler).Methods("GET")        // スケジュール取得
	r.HandleFunc("/delete", deleteScheduleHandler).Methods("POST") //スケジュール削除

	// サーバーの起動
	log.Println("Server is running on http://localhost:8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// 'X-Content-Type-Options' ヘッダーを追加
	w.Header().Set("X-Content-Type-Options", "nosniff")

	tmpl := template.Must(template.ParseFiles("templates/home.html"))
	tmpl.Execute(w, nil)
}

func calendarHandler(w http.ResponseWriter, r *http.Request) {
	// 'X-Content-Type-Options' ヘッダーを追加
	w.Header().Set("X-Content-Type-Options", "nosniff")

	year, month := time.Now().Year(), time.Now().Month()
	queryYear := r.URL.Query().Get("year")
	queryMonth := r.URL.Query().Get("month")

	if queryYear != "" && queryMonth != "" {
		parsedYear, errYear := strconv.Atoi(queryYear)
		parsedMonth, errMonth := strconv.Atoi(queryMonth)
		if errYear == nil && errMonth == nil && parsedMonth >= 1 && parsedMonth <= 12 {
			year = parsedYear
			month = time.Month(parsedMonth)
		}
	}

	firstOfMonth := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
	nextMonthData := firstOfMonth.AddDate(0, 1, 0)
	lastDayOfMonth := nextMonthData.AddDate(0, 0, -1)
	daysInMonth := lastDayOfMonth.Day()

	//daysInMonth := 32 - firstOfMonth.AddDate(0, 0, -32).Day()
	//fmt.Println(firstOfMonth.AddDate(0, 0, -32).Day())
	startWeekday := int(firstOfMonth.Weekday())

	var weeks []Week
	var days []Day

	// データベース接続
	db, err := sql.Open("sqlite3", "./calendar.db")
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		log.Printf("Failed to connect to database: %v", err)
		return
	}
	defer db.Close()

	// 各日付のスケジュールを取得
	scheduleMap := make(map[string]string)
	rows, err := db.Query("SELECT date, content FROM schedules WHERE date LIKE ?", fmt.Sprintf("%04d-%02d-%%", year, int(month)))
	if err != nil {
		//http.Error(w, "Failed to query schedules", http.StatusInternalServerError)
		log.Printf("Failed to query schedules: %v", err)
		//return
	} else {
		defer rows.Close()
		for rows.Next() {
			var date, content string
			if err := rows.Scan(&date, &content); err == nil {
				scheduleMap[date] = content
			} else {
				log.Printf("Error scanning row: %v", err) // ここでエラーが出てもスキップ
			}
		}
	}

	for rows.Next() {
		var date, content string
		if err := rows.Scan(&date, &content); err == nil {
			scheduleMap[date] = content
		}
	}

	// Fill empty days at the start of the month
	for i := 0; i < startWeekday; i++ {
		days = append(days, Day{Empty: true})
	}

	// Fill the actual days of the month
	now := time.Now()
	for day := 1; day <= daysInMonth; day++ {
		date := fmt.Sprintf("%04d-%02d-%02d", year, int(month), day) // 日付の文字列を生成 (例: "2025-01-07")
		days = append(days, Day{
			Date:     day,
			Today:    now.Year() == year && now.Month() == month && now.Day() == day,
			Schedule: scheduleMap[date], // スケジュールがなければ空文字
		})
		if len(days) == 7 {
			weeks = append(weeks, Week{Days: days})
			days = []Day{}
		}
	}

	// Fill empty days at the end of the last week
	for len(days) > 0 && len(days) < 7 {
		days = append(days, Day{Empty: true})
	}
	if len(days) > 0 {
		weeks = append(weeks, Week{Days: days})
	}

	// Calculate previous and next month
	prevYear, prevMonth := year, month-1
	if prevMonth < time.January {
		prevYear--
		prevMonth = time.December
	}
	nextYear, nextMonth := year, month+1
	if nextMonth > time.December {
		nextYear++
		nextMonth = time.January
	}

	data := CalendarData{
		Year:  year,
		Month: month.String(),
		Weeks: weeks,
		Prev:  "/calendar?year=" + strconv.Itoa(prevYear) + "&month=" + strconv.Itoa(int(prevMonth)),
		Next:  "/calendar?year=" + strconv.Itoa(nextYear) + "&month=" + strconv.Itoa(int(nextMonth)),
	}

	tmpl := template.Must(template.ParseFiles("templates/calendar.html"))
	tmpl.Execute(w, data)
}

func saveScheduleHandler(w http.ResponseWriter, r *http.Request) {
	// 'X-Content-Type-Options' ヘッダーを追加
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var schedule Schedule
	if err := json.NewDecoder(r.Body).Decode(&schedule); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	//mutex.Lock()
	//scheduleMap[schedule.Date] = schedule.Content
	//mutex.Unlock()

	db, err := sql.Open("sqlite3", "./calendar.db")
	if err != nil {
		http.Error(w, "Failed to connect to database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO schedules (date, content) VALUES (?, ?)", schedule.Date, schedule.Content)
	if err != nil {
		http.Error(w, "Failed to save schedule", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func getScheduleHandler(w http.ResponseWriter, r *http.Request) {
	// 'X-Content-Type-Options' ヘッダーを追加
	w.Header().Set("X-Content-Type-Options", "nosniff")

	date := r.URL.Query().Get("date")
	/*dateStr := r.URL.Query().Get("date")
	_, err := time.Parse("2006-January-2", dateStr)
	if err != nil {
		http.Error(w, "Invalid date format", http.StatusBadRequest)
		return
	}
	if dateStr == "" {
		http.Error(w, "Date is required", http.StatusBadRequest)
		return
	}*/

	if date == "" {
		http.Error(w, "Date is required", http.StatusBadRequest)
		return
	}

	//mutex.Lock()
	//content, exists := scheduleMap[dateStr]
	//mutex.Unlock()

	//if !exists {
	//	content = ""
	//}

	db, err := sql.Open("sqlite3", "./calendar.db")
	if err != nil {
		http.Error(w, "Failed to connect to database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var content string
	err = db.QueryRow("SELECT content FROM schedules WHERE date = ?", date).Scan(&content)
	if err != nil {
		if err == sql.ErrNoRows {
			content = ""
		} else {
			http.Error(w, "Failed to fetch schedule", http.StatusInternalServerError)
			return
		}
	}

	response := Schedule{
		Date:    date,
		Content: content,
	}
	json.NewEncoder(w).Encode(response)
}

func deleteScheduleHandler(w http.ResponseWriter, r *http.Request) {
	// 'X-Content-Type-Options' ヘッダーを追加
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var schedule Schedule
	if err := json.NewDecoder(r.Body).Decode(&schedule); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	db, err := sql.Open("sqlite3", "./calendar.db")
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		log.Printf("Failed to connect to database: %v", err)
		return
	}
	defer db.Close()

	_, err = db.Exec("DELETE FROM schedules WHERE date = ?", schedule.Date)
	if err != nil {
		http.Error(w, "Failed to delete schedule", http.StatusInternalServerError)
		log.Printf("Failed to delete schedule: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	// 'X-Content-Type-Options' ヘッダーを追加
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method == http.MethodGet {
		tmpl := template.Must(template.ParseFiles("templates/register.html"))
		tmpl.Execute(w, nil)
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			http.Error(w, "Username and password are required", http.StatusBadRequest)
			return
		}

		lock.Lock()
		defer lock.Unlock()

		if _, exists := users[username]; exists {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}

		//passwordHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		//users[username] = User{Username: username, PasswordHash: passwordHash}

		// ハッシュ化されたパスワードを作成
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}

		// データベースに保存
		db, err := sql.Open("sqlite3", "./calendar.db")
		if err != nil {
			http.Error(w, "Failed to connect to database", http.StatusInternalServerError)
			return
		}
		defer db.Close()

		_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, string(passwordHash))
		if err != nil {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// 'X-Content-Type-Options' ヘッダーを追加
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method == http.MethodGet {
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, nil)
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			http.Error(w, "Username and password are required", http.StatusBadRequest)
			return
		}

		// データベース接続を取得
		db, err := sql.Open("sqlite3", "./calendar.db")
		if err != nil {
			http.Error(w, "Database connection error", http.StatusInternalServerError)
			log.Printf("Failed to connect to database: %v", err)
			return
		}
		defer db.Close()

		// ユーザー情報を取得
		var storedPassword string
		err = db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			} else {
				http.Error(w, "Database query error", http.StatusInternalServerError)
				log.Printf("Failed to query user: %v", err)
			}
			return
		}

		// パスワードの検証
		if bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password)) != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// ログイン成功時のリダイレクト
		http.Redirect(w, r, "/calendar", http.StatusSeeOther)
	}
}

/*func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, nil)
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		lock.Lock()
		user, exists := users[username]
		lock.Unlock()

		if !exists || bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)) != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		http.Redirect(w, r, "/calendar", http.StatusSeeOther)
	}
}*/
