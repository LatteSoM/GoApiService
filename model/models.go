package model

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

type Status struct {
	ID         uint   `json:"id"`
	StatusName string `json:"status_name" validate:"required"`
}

type ResponseUserCreateStatus struct {
	Answer ResponseUser `json:"answer"`
	Data   Status       `json:"data"`
}

type ResponseUserCreateStatusArr struct {
	Answer ResponseUser `json:"answer"`
	Data   []Status     `json:"data"`
}

type ResponseUser struct {
	ID      uint   `json:"id"`
	Message string `json:"message"`
}

type User struct {
	ID          uint      `json:"id"`
	KeycloackId string    `json:"keycloack_id" validate:"required"`
	Surname     string    `json:"surname" validate:"required"`
	Name        string    `json:"name" validate:"required"`
	Patronymic  string    `json:"patronymic" validate:"required"`
	DateOfBirth time.Time `json:"date_of_birth" validate:"required"`
	StatusId    uint      `json:"status_id" validate:"required"`
	Email       string    `json:"email" validate:"required"`
	Discord     string    `json:"discord" validate:"required"`
	Telegram    string    `json:"telegram" validate:"required"`
	CanEnter    bool      `json:"can_enter" validate:"required"`
}

type ResponseUserCreateUser struct {
	Answer ResponseUser `json:"answer"`
	Data   User         `json:"data"`
}

type ResponseUserCreateUserArr struct {
	Answer ResponseUser `json:"answer"`
	Data   []User       `json:"data_arr"`
}

type Logs struct {
	ID     uint `json:"id"`
	UserId uint `json:"user_id" validate:"required"`
	//User   User      `json:"user" gorm:"foreignKey:UserId;references:ID"`
	Action string    `json:"action" validate:"required"`
	Date   time.Time `json:"date" validate:"required"`
}

type ResponseUserCreateLogs struct {
	Answer ResponseUser `json:"answer"`
	Data   Logs         `json:"data"`
}

type ResponseUserCreateLogsArr struct {
	Answer ResponseUser `json:"answer"`
	Data   []Logs       `json:"data"`
}

type GroupMPT struct {
	ID          uint   `json:"id"`
	GroupNumber string `json:"group_number" validate:"required"`
}

type ResponseUserCreateGroupMPT struct {
	Answer ResponseUser `json:"answer"`
	Data   GroupMPT     `json:"data"`
}

type ResponseUserCreateGroupMPTArr struct {
	Answer ResponseUser `json:"answer"`
	Data   []GroupMPT   `json:"data"`
}

type GroupMarlo struct {
	ID          uint   `json:"id"`
	GroupNumber string `json:"group_number"`
}

type ResponseUserCreateGroupMarlo struct {
	Answer ResponseUser `json:"answer"`
	Data   GroupMarlo   `json:"data"`
}

type ResponseUserCreateGroupMarloArr struct {
	Answer ResponseUser `json:"answer"`
	Data   []GroupMarlo `json:"data"`
}

type Practices struct {
	ID           uint      `json:"id"`
	PracticeName string    `json:"practice_name" validate:"required"`
	Start        time.Time `json:"start" validate:"required"`
	End          time.Time `json:"end" validate:"required"`
}

type ResponseUserCreatePractice struct {
	Answer ResponseUser `json:"answer"`
	Data   Practices    `json:"data"`
}

type ResponseUserCreatePracticeArr struct {
	Answer ResponseUser `json:"answer"`
	Data   []Practices  `json:"data"`
}

type PracticeConfig struct {
	ID           uint `json:"id" validate:"required"`
	PracticeId   uint `json:"practice_id" validate:"required"`
	StudentId    uint `json:"student_id" validate:"required"`
	SupervisorId uint `json:"supervisor_id" validate:"required"`
	GroupMPTId   uint `json:"group_mpt_id" validate:"required"`
	GroupMarloId uint `json:"group_marlo_id" validate:"required"`
}

type ResponseUserCreatePracticeConfig struct {
	Answer ResponseUser   `json:"answer"`
	Data   PracticeConfig `json:"data"`
}

type ResponseUserCreatePracticeConfigArr struct {
	Answer ResponseUser     `json:"answer"`
	Data   []PracticeConfig `json:"data"`
}

type PracticeDays struct {
	ID  uint   `json:"id"`
	Day string `json:"day" validate:"required"`
}

type ResponseUserCreatePracticedays struct {
	Answer ResponseUser `json:"answer"`
	Data   PracticeDays `json:"data"`
}

type ResponseUserCreatePracticedaysArr struct {
	Answer ResponseUser   `json:"answer"`
	Data   []PracticeDays `json:"data"`
}

type PracticeShedule struct {
	ID               uint `json:"id"`
	DayId            uint `json:"day"`
	PracticeConfigId uint `json:"practice_config_id"`
}

type ResponseUserCreatepracticeShedule struct {
	Answer ResponseUser    `json:"answer"`
	Data   PracticeShedule `json:"data"`
}

type ResponseUserCreatepracticeSheduleArr struct {
	Answer ResponseUser      `json:"answer"`
	Data   []PracticeShedule `json:"data"`
}

func Auth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"response": gin.H{
			"method": http.MethodGet,
			"code":   http.StatusOK,
			"message": gin.H{
				//"goods": database.GetDb().Find(&model.Goods{}),
				//"goods": database.Get_goods(),
				"aaaaaaaaa": "asdasdasdasdasd", //func auth
			},
		},
	})
}
