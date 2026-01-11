package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/joho/godotenv"
	_ "modernc.org/sqlite"
)

// SpamDetector holds spam detection rules
type SpamDetector struct {
	// Suspicious patterns
	linkPattern    *regexp.Regexp
	mentionPattern *regexp.Regexp
	spamKeywords   []string
	// Database connection
	db           *sql.DB
	banThreshold int
}

func NewSpamDetector() (*SpamDetector, error) {
	// Open SQLite database
	db, err := sql.Open("sqlite", "spambot.db")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Create table if not exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS spam_records (
			chat_id INTEGER,
			user_id INTEGER,
			count INTEGER DEFAULT 0,
			PRIMARY KEY (chat_id, user_id)
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to create table: %v", err)
	}

	return &SpamDetector{
		linkPattern:    regexp.MustCompile(`(?i)(https?://|t\.me/|bit\.ly|tinyurl|telegram\.me|www\.|[a-z0-9][-a-z0-9]*\.(com|net|org|io|me|co|xyz|info|biz|tv|cc|ru|kr|cn)\b)`),
		mentionPattern: regexp.MustCompile(`@[a-zA-Z0-9_]+`),
		spamKeywords: []string{
			"earn money", "make money fast", "investment opportunity",
			"double your", "guaranteed profit", "free money",
			"click here", "join now", "limited time offer",
			"act now", "don't miss", "exclusive deal",
			"work from home", "be your own boss", "financial freedom",
			"forex signal", "trading signal", "casino", "betting",
		},
		db:           db,
		banThreshold: 3,
	}, nil
}

// RecordSpam increments spam count for user and returns (current count, should ban)
func (sd *SpamDetector) RecordSpam(chatID int64, userID int64) (int, bool) {
	// Upsert: insert or update spam count
	_, err := sd.db.Exec(`
		INSERT INTO spam_records (chat_id, user_id, count) VALUES (?, ?, 1)
		ON CONFLICT(chat_id, user_id) DO UPDATE SET count = count + 1
	`, chatID, userID)
	if err != nil {
		log.Printf("Failed to record spam: %v", err)
		return 0, false
	}

	// Get current count
	var count int
	err = sd.db.QueryRow(`
		SELECT count FROM spam_records WHERE chat_id = ? AND user_id = ?
	`, chatID, userID).Scan(&count)
	if err != nil {
		log.Printf("Failed to get spam count: %v", err)
		return 0, false
	}

	return count, count >= sd.banThreshold
}

// Close closes the database connection
func (sd *SpamDetector) Close() {
	if sd.db != nil {
		sd.db.Close()
	}
}

func (sd *SpamDetector) IsSpam(text string) (bool, string, string) {
	lowerText := strings.ToLower(text)

	// Check if message has URL or mention
	hasLink := sd.linkPattern.MatchString(text)
	hasMention := sd.mentionPattern.MatchString(text)

	// URL = always spam
	if hasLink {
		return true, "URL detected", "URL 감지"
	}

	// Spam keyword + mention = spam
	if hasMention {
		for _, keyword := range sd.spamKeywords {
			if strings.Contains(lowerText, keyword) {
				return true, "spam keyword with mention: " + keyword, "멘션+스팸 키워드"
			}
		}
	}

	return false, "", ""
}

func main() {
	// Load .env file
	godotenv.Load()

	// Create log file
	logFile, err := os.OpenFile("bot.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// Get bot token from environment variable
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	if token == "" {
		log.Fatal("TELEGRAM_BOT_TOKEN environment variable is not set")
	}

	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatalf("Failed to create bot: %v", err)
	}

	log.Printf("Authorized on account %s", bot.Self.UserName)

	detector, err := NewSpamDetector()
	if err != nil {
		log.Fatalf("Failed to create spam detector: %v", err)
	}
	defer detector.Close()

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		// Check message text
		text := update.Message.Text
		if update.Message.Caption != "" {
			text = update.Message.Caption
		}

		if text == "" {
			continue
		}

		// 디버깅: 모든 수신 메시지 로깅 (관리자 확인 전으로 이동)
		log.Printf("Received message from %s (ID: %d) in %s (%s): %s",
			update.Message.From.UserName,
			update.Message.From.ID,
			update.Message.Chat.Title,
			update.Message.Chat.Type,
			text)

		// Skip messages from admins
		if update.Message.Chat.Type != "private" {
			chatMember, err := bot.GetChatMember(tgbotapi.GetChatMemberConfig{
				ChatConfigWithUser: tgbotapi.ChatConfigWithUser{
					ChatID: update.Message.Chat.ID,
					UserID: update.Message.From.ID,
				},
			})
			if err == nil && (chatMember.Status == "administrator" || chatMember.Status == "creator") {
				log.Printf("Ignoring message from admin %s", update.Message.From.UserName)
				continue // Don't check admin messages
			}
		}

		// Handle commands
		if update.Message.IsCommand() {
			switch update.Message.Command() {
			case "start":
				msg := tgbotapi.NewMessage(update.Message.Chat.ID,
					"I'm a spam/ad blocking bot. Add me to your group as an admin and I'll help keep it clean!\n\n"+
						"Commands:\n"+
						"/start - Show this message\n"+
						"/status - Check if bot is working")
				bot.Send(msg)
			case "status":
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Bot is active and monitoring for spam.")
				bot.Send(msg)
			}
			continue
		}

		// Check for spam in group chats
		if update.Message.Chat.Type == "group" || update.Message.Chat.Type == "supergroup" {
			isSpam, reason, reasonKR := detector.IsSpam(text)
			if isSpam {
				// Delete the spam message
				log.Printf("Detected spam from %s (reason: %s), attempting to delete...",
					update.Message.From.UserName, reason)
				deleteMsg := tgbotapi.NewDeleteMessage(update.Message.Chat.ID, update.Message.MessageID)
				_, err := bot.Request(deleteMsg)
				if err != nil {
					log.Printf("Failed to delete message ID %d from chat %d: %v",
						update.Message.MessageID, update.Message.Chat.ID, err)
				} else {
					log.Printf("Successfully deleted spam message from %s (reason: %s)",
						update.Message.From.UserName, reason)

					// Record spam and check if user should be banned
					count, shouldBan := detector.RecordSpam(update.Message.Chat.ID, update.Message.From.ID)

					if shouldBan {
						// Ban the user
						banConfig := tgbotapi.BanChatMemberConfig{
							ChatMemberConfig: tgbotapi.ChatMemberConfig{
								ChatID: update.Message.Chat.ID,
								UserID: update.Message.From.ID,
							},
						}
						_, banErr := bot.Request(banConfig)
						if banErr != nil {
							log.Printf("Failed to ban user %s: %v", update.Message.From.UserName, banErr)
						} else {
							log.Printf("Banned user %s for repeated spam", update.Message.From.UserName)
							notifyMsg := tgbotapi.NewMessage(update.Message.Chat.ID,
								fmt.Sprintf("🚫 @%s 님이 스팸 %d회로 차단되었습니다 [%s]", update.Message.From.UserName, count, reasonKR))
							bot.Send(notifyMsg)
						}
					} else {
						// Send warning message with count
						notifyMsg := tgbotapi.NewMessage(update.Message.Chat.ID,
							fmt.Sprintf("🚫 @%s 스팸 삭제 [%s] (경고 %d/3)", update.Message.From.UserName, reasonKR, count))
						bot.Send(notifyMsg)
					}
				}
			}
		}
	}
}
