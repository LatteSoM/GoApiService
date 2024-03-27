package initializers

import (
	"github.com/joho/godotenv"
	"log"
)

func EnvInitializer() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error of load the .env file!")
		//return
	}
	log.Println("success .env file load")
}
