package database

import (
	"MarloService/model"
	"fmt"
	//"github.com/jinzhu/gorm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"time"
)

var dbase *gorm.DB

func Init() *gorm.DB {
	//db, err := gorm.Open("postgres", "user=postgres password=1234 dbname=pract sslmode=disable port=9000")

	dsn := "host=localhost user=postgres password=1234 dbname=pract port=9000 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic(err)
	}

	db.AutoMigrate(&model.GroupMPT{}, &model.Practices{}, &model.GroupMarlo{}, &model.PracticeDays{}, &model.Status{},
		&model.User{}, &model.Logs{}, &model.PracticeConfig{}, &model.PracticeShedule{})
	return db
}

func GetDb() *gorm.DB {
	if dbase == nil {
		dbase = Init()
		var sleep = time.Duration(1)
		for dbase == nil {
			sleep = sleep * 2
			fmt.Printf("databsde is nedostupna, wait for %d seconds /d", sleep)
			time.Sleep(sleep * time.Second)
			dbase = Init()
		}
	}
	return dbase
}
