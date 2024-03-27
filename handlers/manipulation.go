package handlers

import (
	"MarloService/database"
	"MarloService/model"
	"encoding/base64"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"strings"
	//"github.com/golang-jwt/jwt/v4"
	"net/http"
)

var db = database.GetDb()

//func TokenAuthMiddleware(requestedRoles []string) gin.HandlerFunc {
//	return func(c *gin.Context) {
//		//type Token struct {
//		//	Token string `json:"token"`
//		//}
//
//		//var requestBody Token
//		//if err := c.ShouldBindJSON(&requestBody); err != nil {
//		//	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
//		//	c.Abort()
//		//	return
//		//}
//
//		//tokenString := requestBody.Token
//
//		var tokenString = c.Request.Header.Get("Authorization")
//		log.Printf(tokenString)
//
//		segments := strings.Split(tokenString, ".")
//		payloadSegment, _ := base64.RawURLEncoding.DecodeString(segments[1])
//
//		var payload map[string]interface{}
//		json.Unmarshal(payloadSegment, &payload)
//
//		roles, ok := payload["realm_access"].(map[string]interface{})["roles"].([]interface{})
//		if !ok {
//			fmt.Println("Невозможно получить список ролей")
//			return
//		}
//
//		//requiredRole := "emolie_role"
//		roleExists := false
//
//		for _, requiredRole := range requestedRoles {
//			for _, role := range roles {
//				if role == requiredRole {
//					roleExists = true
//					break
//				}
//			}
//			if roleExists {
//				break
//			}
//		}
//
//		if roleExists {
//			c.Next()
//		} else {
//			c.JSON(404, gin.H{"Роль не присутствует": "это сработал миддлеваре"})
//		}
//
//		c.Next()
//	}
//}

func TokenAuthMiddleware(requestedRoles []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Отсутствует заголовок авторизации"})
			c.Abort()
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Некорректный формат токена"})
			c.Abort()
			return
		}

		tokenString := bearerToken[1]

		segments := strings.Split(tokenString, ".")
		if len(segments) != 3 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Некорректный токен"})
			c.Abort()
			return
		}

		payloadSegment, err := base64.RawURLEncoding.DecodeString(segments[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Ошибка декодирования токена"})
			c.Abort()
			return
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(payloadSegment, &payload); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Ошибка разбора полезной нагрузки токена"})
			c.Abort()
			return
		}

		realmAccess, ok := payload["realm_access"].(map[string]interface{})
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Невозможно получить список ролей"})
			c.Abort()
			return
		}

		roles, ok := realmAccess["roles"].([]interface{})
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Невозможно получить список ролей"})
			c.Abort()
			return
		}

		for _, requiredRole := range requestedRoles {
			for _, role := range roles {
				if role == requiredRole {
					c.Next()
					return
				}
			}
		}

		c.JSON(http.StatusForbidden, gin.H{"error": "Роль не присутствует"})
		c.Abort()
		return
	}
}

// @Summary ShortLink
// @Description Update short link
// @Accept  json
// @Produce  json
// FindAllTags     godoc
// @Tags      ShortLink
// @Accept json
// @Schemes
// @Produce json
// @Success      200  {array}  model.GroupMPT
// @Failure 503 {object} model.GroupMarlo "Технический перерыв"
// @Router /get_auth [get]
// @Security Bearer
func Arr(c *gin.Context) {
	roleExists := true

	if roleExists {
		//fmt.Printf("Роль %s присутствует в разделе realm_access.roles\n", requiredRole)
		//c.JSON(200, gin.H{"Мидлваре отработал Роль присутствует в разделе realm_access.roles": requiredRole})
		c.JSON(200, gin.H{"Роль присутствует в разделе realm_access.roles": 1})
	}
}

// @Summary SearchUsers in database
// @Description Searching  all users by name
// @Tags User
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateUserArr
// @Failure 500 {object} model.ResponseUserCreateUserArr "Технические шоколадки"
// @Router /user_all [get]
// @Security Bearer
func Search(c *gin.Context) {
	var users []model.User
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateUserArr
	searchParam := c.Query("item")
	result := db.Where("name = ?", searchParam).Find(&users)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      0,
			Message: "Error fetching data from database",
		}
		Response = model.ResponseUserCreateUserArr{Answer: UserMessage, Data: users}
		c.JSON(500, gin.H{"error": Response})
		return
	}
	UserMessage = model.ResponseUser{
		ID:      0,
		Message: "Fetching data <Users> from data base is succes",
	}
	Response = model.ResponseUserCreateUserArr{Answer: UserMessage, Data: users}
	c.JSON(200, Response)

}

// @Summary Read All GroupMPT records
// @Description Reading a GroupMPT items
// @Tags GroupMPT
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateGroupMPTArr
// @Failure 500 {object} model.ResponseUserCreateGroupMPTArr "Технические шоколадки"
// @Router /groupmpt_all [get]
// @Security Bearer
func GetAllGroupMPT(c *gin.Context) {
	var groups []model.GroupMPT
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateGroupMPTArr
	result := db.Find(&groups)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      0,
			Message: "Error fetching data from database",
		}
		Response = model.ResponseUserCreateGroupMPTArr{Answer: UserMessage, Data: groups}
		c.JSON(500, gin.H{"error": Response})
		return
	}
	UserMessage = model.ResponseUser{
		ID:      0,
		Message: "Fetching data <GroupMPT> from data base is succes",
	}
	Response = model.ResponseUserCreateGroupMPTArr{Answer: UserMessage, Data: groups}
	c.JSON(200, Response)
}

// @Summary Read All GroupMPT records
// @Description Reading a GroupMarlo all items
// @Tags GroupMarlo
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateGroupMarloArr
// @Failure 500 {object} model.ResponseUserCreateGroupMarloArr "Технические шоколадки"
// @Router /groupmarlo_all [get]
// @Security Bearer
func GetAllGroupMarlo(c *gin.Context) {
	var groups []model.GroupMarlo
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateGroupMarloArr
	result := db.Find(&groups)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      0,
			Message: "Error fetching data from database",
		}
		Response = model.ResponseUserCreateGroupMarloArr{Answer: UserMessage, Data: groups}
		c.JSON(500, gin.H{"error": Response})
		return
	}
	UserMessage = model.ResponseUser{
		ID:      0,
		Message: "Fetching data <GroupMarlo> from data base is succes",
	}
	Response = model.ResponseUserCreateGroupMarloArr{Answer: UserMessage, Data: groups}
	c.JSON(200, Response)
}

// @Summary Read all users
// @Description Reading all users
// @Tags User
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateUserArr
// @Failure 500 {object} model.ResponseUserCreateUserArr "Технические шоколадки"
// @Router /user_all [get]
// @Security Bearer
func GetAllUsers(c *gin.Context) {
	var users []model.User
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateUserArr
	result := db.Find(&users)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      0,
			Message: "Error fetching data from database",
		}
		Response = model.ResponseUserCreateUserArr{Answer: UserMessage, Data: users}
		c.JSON(500, gin.H{"error": Response})
		return
	}
	UserMessage = model.ResponseUser{
		ID:      0,
		Message: "Fetching data <Users> from data base is succes",
	}
	Response = model.ResponseUserCreateUserArr{Answer: UserMessage, Data: users}
	c.JSON(200, Response)
}

// @Summary Read all status
// @Description Reading all status
// @Tags Status
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateStatusArr
// @Failure 500 {object} model.ResponseUserCreateStatusArr "Технические шоколадки"
// @Router /status_all [get]
// @Security Bearer
func GetAllStatus(c *gin.Context) {
	var statuses []model.Status
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateStatusArr
	result := db.Find(&statuses)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      0,
			Message: "Error fetching data from database",
		}
		Response = model.ResponseUserCreateStatusArr{Answer: UserMessage, Data: statuses}
		c.JSON(500, gin.H{"error": Response})
		return
	}
	UserMessage = model.ResponseUser{
		ID:      0,
		Message: "Fetching data <Status> from data base is succes",
	}
	Response = model.ResponseUserCreateStatusArr{Answer: UserMessage, Data: statuses}
	c.JSON(200, Response)
}

// @Summary Read all Logs
// @Description Reading all logs
// @Tags Logs
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateLogsArr
// @Failure 500 {object} model.ResponseUserCreateLogsArr "Технические шоколадки"
// @Router /status_all [get]
// @Security Bearer
func GetAllLogs(c *gin.Context) {
	var logs []model.Logs
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateLogsArr
	result := db.Find(&logs)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      0,
			Message: "Error fetching data from database",
		}
		Response = model.ResponseUserCreateLogsArr{Answer: UserMessage, Data: logs}
		c.JSON(500, gin.H{"error": Response})
		return
	}
	UserMessage = model.ResponseUser{
		ID:      0,
		Message: "Fetching data <Logs> from data base is succes",
	}
	Response = model.ResponseUserCreateLogsArr{Answer: UserMessage, Data: logs}
	c.JSON(200, Response)
}

// @Summary Read all practices
// @Description Reading all practices
// @Tags Practices
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePracticeArr
// @Failure 500 {object} model.ResponseUserCreatePracticeArr "Технические шоколадки"
// @Router /practice_all [get]
// @Security Bearer
func GetAllPractices(c *gin.Context) {
	var practices []model.Practices
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePracticeArr
	result := db.Find(&practices)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      0,
			Message: "Error fetching data from database",
		}
		Response = model.ResponseUserCreatePracticeArr{Answer: UserMessage, Data: practices}
		c.JSON(500, gin.H{"error": Response})
		return
	}
	UserMessage = model.ResponseUser{
		ID:      0,
		Message: "Fetching data <Practice> from data base is succes",
	}
	Response = model.ResponseUserCreatePracticeArr{Answer: UserMessage, Data: practices}
	c.JSON(200, Response)
}

// @Summary Read all practices configs
// @Description Reading all practices configs
// @Tags PracticeConfig
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePracticeConfigArr
// @Failure 500 {object} model.ResponseUserCreatePracticeConfigArr "Технические шоколадки"
// @Router /practiceconfig_all [get]
// @Security Bearer
func GetAllPracticeConfigs(c *gin.Context) {
	var configs []model.PracticeConfig
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePracticeConfigArr
	result := db.Find(&configs)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      0,
			Message: "Error fetching data from database",
		}
		Response = model.ResponseUserCreatePracticeConfigArr{Answer: UserMessage, Data: configs}
		c.JSON(500, gin.H{"error": Response})
		return
	}
	UserMessage = model.ResponseUser{
		ID:      0,
		Message: "Fetching data <PracticeConfigs> from data base is succes",
	}
	Response = model.ResponseUserCreatePracticeConfigArr{Answer: UserMessage, Data: configs}
	c.JSON(200, Response)
}

// @Summary Read all practices days
// @Description Reading all practices days
// @Tags PracticeDays
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePracticedaysArr
// @Failure 500 {object} model.ResponseUserCreatePracticedaysArr "Технические шоколадки"
// @Router /practiceday_all [get]
// @Security Bearer
func GetAllPracticeDays(c *gin.Context) {
	var days []model.PracticeDays
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePracticedaysArr
	result := db.Find(&days)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      0,
			Message: "Error fetching data from database",
		}
		Response = model.ResponseUserCreatePracticedaysArr{Answer: UserMessage, Data: days}
		c.JSON(500, gin.H{"error": Response})
		return
	}
	UserMessage = model.ResponseUser{
		ID:      0,
		Message: "Fetching data <PracticeDays> from data base is succes",
	}
	Response = model.ResponseUserCreatePracticedaysArr{Answer: UserMessage, Data: days}
	c.JSON(200, Response)
}

// @Summary Read all practice shedule
// @Description Reading all practice shedule
// @Tags PracticeShedule
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatepracticeSheduleArr
// @Failure 500 {object} model.ResponseUserCreatepracticeSheduleArr "Технические шоколадки"
// @Router /practiceschedule_all [get]
// @Security Bearer
func GetAllShedule(c *gin.Context) {
	var practiceShedules []model.PracticeShedule
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatepracticeSheduleArr
	result := db.Find(&practiceShedules)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      0,
			Message: "Error fetching data from database",
		}
		Response = model.ResponseUserCreatepracticeSheduleArr{Answer: UserMessage, Data: practiceShedules}
		c.JSON(500, gin.H{"error": Response})
		return
	}
	UserMessage = model.ResponseUser{
		ID:      0,
		Message: "Fetching data <PracticeShedule> from data base is succes",
	}
	Response = model.ResponseUserCreatepracticeSheduleArr{Answer: UserMessage, Data: practiceShedules}
	c.JSON(200, Response)
}

// @Summary Create group mpt
// @Description create item of mpt group
// @Tags GroupMPT
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateGroupMPT
// @Failure 503 {object} model.ResponseUserCreateGroupMPT "Технические шоколадки"
// @Param body body model.GroupMPT true "GroupMPT object that needs to be found"
// @Router /groupmpt [post]
// @Security Bearer
func CreateGroupMPT(c *gin.Context) {
	var groupMPT model.GroupMPT
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateGroupMPT

	if err := c.ShouldBindJSON(&groupMPT); err != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMPT.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateGroupMPT{Answer: UserMessage, Data: groupMPT}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	var validate = validator.New()
	if err := validate.Struct(groupMPT); err != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMPT.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateGroupMPT{Answer: UserMessage, Data: groupMPT}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Create(&groupMPT)
	UserMessage = model.ResponseUser{
		ID:      groupMPT.ID,
		Message: "GroupMPT created successfully",
	}
	Response = model.ResponseUserCreateGroupMPT{Answer: UserMessage, Data: groupMPT}
	c.JSON(http.StatusOK, gin.H{"Message": Response})
	//c.JSON(http.StatusOK, gin.H{"error": "sdfghjkl;"})
}

// @Summary Read a GroupMPT by id
// @Description Reading a GroupMPT item by id
// @Tags GroupMPT
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateGroupMPT
// @Failure 503 {object} model.ResponseUserCreateGroupMPT "Технические шоколадки"
// @Param        id   path      int  true  "Account ID"
// @Router /groupmpt/{id} [get]
// @Security Bearer
func ReadGroupMPTByID(c *gin.Context) {
	id := c.Params.ByName("id")
	var groupMPT model.GroupMPT
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateGroupMPT
	result := db.First(&groupMPT, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMPT.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateGroupMPT{Answer: UserMessage, Data: groupMPT}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}
	UserMessage = model.ResponseUser{
		ID:      groupMPT.ID,
		Message: "Record found succes",
	}
	Response = model.ResponseUserCreateGroupMPT{Answer: UserMessage, Data: groupMPT}

	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary update a GroupMPT
// @Description Create a new GroupMPT record
// @Tags GroupMPT
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateGroupMPT
// @Failure 503 {object} model.ResponseUserCreateGroupMPT "Технические шоколадки"
// @Param body body model.GroupMPT true "GroupMPT object that needs to be updated"
// / @Param        id   path      int  true  "Account ID"
// @Router /groupmpt/{id} [put]
// @Security Bearer
func UpdateGroupMPT(c *gin.Context) {
	id := c.Params.ByName("id")
	var groupMPT model.GroupMPT
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateGroupMPT
	result := db.First(&groupMPT, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMPT.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateGroupMPT{Answer: UserMessage, Data: groupMPT}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	var validate = validator.New()
	if err := validate.Struct(groupMPT); err != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMPT.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateGroupMPT{Answer: UserMessage, Data: groupMPT}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	if err := c.ShouldBindJSON(&groupMPT); err != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMPT.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateGroupMPT{Answer: UserMessage, Data: groupMPT}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Save(&groupMPT)
	UserMessage = model.ResponseUser{
		ID:      groupMPT.ID,
		Message: "GroupMPT Updated successfully",
	}
	Response = model.ResponseUserCreateGroupMPT{Answer: UserMessage, Data: groupMPT}
	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Delete a GroupMPT
// @Description Delete a GroupMPT record
// @Tags GroupMPT
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateGroupMPT
// @Failure 503 {object} model.ResponseUserCreateGroupMPT "Технические шоколадки"
// @Param body body model.GroupMPT true "GroupMPT object that needs to be deleted"
// / @Param        id   path      int  true  "Account ID"
// @Router /groupmpt/{id}  [delete]
// @Security Bearer
func DeleteGroupMPT(c *gin.Context) {
	id := c.Params.ByName("id")
	var groupMPT model.GroupMPT
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateGroupMPT
	result := db.First(&groupMPT, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMPT.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateGroupMPT{Answer: UserMessage, Data: groupMPT}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	db.Delete(&groupMPT, id)
	UserMessage = model.ResponseUser{
		ID:      groupMPT.ID,
		Message: "GroupMPT Deleted successfully",
	}
	Response = model.ResponseUserCreateGroupMPT{Answer: UserMessage, Data: groupMPT}
	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// / @Summary Create a GroupMarlo
// @Description Create a GroupMarlo record
// @Tags GroupMarlo
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateGroupMarlo
// @Failure 503 {object} model.ResponseUserCreateGroupMarlo "Технические шоколадки"
// @Param body body model.GroupMarlo true "GroupMarlo object that needs to be created"
// @Router /groupmarlo [post]
// @Security Bearer
func CreateGroupMarlo(c *gin.Context) {
	var groupMarlo model.GroupMarlo
	//if err := c.ShouldBindJSON(&groupMarlo); err != nil {
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	//	return
	//}
	//db.Create(&groupMarlo)
	//c.JSON(http.StatusOK, gin.H{"message": "GroupMarlo created successfully", "data": groupMarlo})
	//
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateGroupMarlo
	if err := c.ShouldBindJSON(&groupMarlo); err != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMarlo.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateGroupMarlo{Answer: UserMessage, Data: groupMarlo}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	var validate = validator.New()
	if err := validate.Struct(groupMarlo); err != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMarlo.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateGroupMarlo{Answer: UserMessage, Data: groupMarlo}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Create(&groupMarlo)
	UserMessage = model.ResponseUser{
		ID:      groupMarlo.ID,
		Message: "GroupMarlo created successfully",
	}
	Response = model.ResponseUserCreateGroupMarlo{Answer: UserMessage, Data: groupMarlo}

	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Reade a GroupMarlo
// @Description Reade a GroupMarlo record
// @Tags GroupMarlo
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateGroupMarlo
// @Failure 503 {object} model.ResponseUserCreateGroupMarlo "Технические шоколадки"
// @Param        id   path      int  true  "Account ID"
// @Router /groupmarlo/{id} [get]
// @Security Bearer
func ReadGroupMarloByID(c *gin.Context) {
	id := c.Params.ByName("id")
	var groupMarlo model.GroupMarlo
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateGroupMarlo
	result := db.First(&groupMarlo, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMarlo.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateGroupMarlo{Answer: UserMessage, Data: groupMarlo}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}
	UserMessage = model.ResponseUser{
		ID:      groupMarlo.ID,
		Message: "Record found succes",
	}
	Response = model.ResponseUserCreateGroupMarlo{Answer: UserMessage, Data: groupMarlo}

	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary UPDATE a GroupMarlo
// @Description Update a GroupMarlo record
// @Tags GroupMarlo
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateGroupMarlo
// @Failure 503 {object} model.ResponseUserCreateGroupMarlo "Технические шоколадки"
// @Param body body model.GroupMarlo true "GroupMarlo object that needs to be Updated"
// / @Param        id   path      int  true  "Account ID"
// @Router /groupmarlo/{id} [put]
// @Security Bearer
func UpdateGroupMarlo(c *gin.Context) {
	id := c.Params.ByName("id")
	var groupMarlo model.GroupMarlo
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateGroupMarlo
	result := db.First(&groupMarlo, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMarlo.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateGroupMarlo{Answer: UserMessage, Data: groupMarlo}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	var validate = validator.New()
	if err := validate.Struct(groupMarlo); err != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMarlo.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateGroupMarlo{Answer: UserMessage, Data: groupMarlo}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	if err := c.ShouldBindJSON(&groupMarlo); err != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMarlo.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateGroupMarlo{Answer: UserMessage, Data: groupMarlo}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Save(&groupMarlo)
	UserMessage = model.ResponseUser{
		ID:      groupMarlo.ID,
		Message: "GroupMarlo Updated successfully",
	}
	Response = model.ResponseUserCreateGroupMarlo{Answer: UserMessage, Data: groupMarlo}
	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary DELETE a GroupMarlo
// @Description Reade a GroupMarlo record
// @Tags GroupMarlo
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateGroupMarlo
// @Failure 503 {object} model.ResponseUserCreateGroupMarlo "Технические шоколадки"
// @Param body body model.GroupMarlo true "GroupMarlo object that needs to be deleted"
// / @Param        id   path      int  true  "Account ID"
// @Router /groupmarlo/{id} [delete]
// @Security Bearer
func DeleteGroupMarlo(c *gin.Context) {
	id := c.Params.ByName("id")
	var groupMarlo model.GroupMarlo
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateGroupMarlo
	result := db.First(&groupMarlo, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      groupMarlo.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateGroupMarlo{Answer: UserMessage, Data: groupMarlo}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	db.Delete(&groupMarlo, id)
	UserMessage = model.ResponseUser{
		ID:      groupMarlo.ID,
		Message: "GroupMarlo Deleted successfully",
	}
	Response = model.ResponseUserCreateGroupMarlo{Answer: UserMessage, Data: groupMarlo}
	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary Create a new user
// @Description Create a new user record
// @Tags User
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateUser
// @Failure 503 {object} model.ResponseUserCreateUser "Технические шоколадки"
// @Param body body model.User true "User object that needs to be created"
// @Router /user [post]
// @Security Bearer
func CreateUser(c *gin.Context) {
	var user model.User
	//if err := c.ShouldBindJSON(&user); err != nil {
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	//	return
	//}
	//db.Create(&user)
	//c.JSON(http.StatusOK, gin.H{"message": "User created successfully", "data": user})

	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateUser
	if err := c.ShouldBindJSON(&user); err != nil {
		UserMessage = model.ResponseUser{
			ID:      user.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateUser{Answer: UserMessage, Data: user}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	var validate = validator.New()
	if err := validate.Struct(user); err != nil {
		UserMessage = model.ResponseUser{
			ID:      user.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateUser{Answer: UserMessage, Data: user}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Create(&user)
	UserMessage = model.ResponseUser{
		ID:      user.ID,
		Message: "user created successfully",
	}
	Response = model.ResponseUserCreateUser{Answer: UserMessage, Data: user}

	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Read a user by id
// @Description Reading a user item by id
// @Tags User
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateUser
// @Failure 503 {object} model.ResponseUserCreateUser "Технические шоколадки"
// @Param        id   path      int  true  "Account ID"
// @Router /user/{id} [get]
// @Security Bearer
func ReadUserByID(c *gin.Context) {
	id := c.Params.ByName("id")
	var user model.User
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateUser
	result := db.First(&user, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      user.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateUser{Answer: UserMessage, Data: user}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}
	UserMessage = model.ResponseUser{
		ID:      user.ID,
		Message: "Record found succes",
	}
	Response = model.ResponseUserCreateUser{Answer: UserMessage, Data: user}

	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary Update a user
// @Description Update a user record
// @Tags User
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateUser
// @Failure 503 {object} model.ResponseUserCreateUser "Технические шоколадки"
// @Param body body model.User true "User object that needs to be updated"
// / @Param        id   path      int  true  "Account ID"
// @Router /user/{id} [put]
// @Security Bearer
func UpdateUser(c *gin.Context) {
	id := c.Params.ByName("id")
	var user model.User
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateUser
	result := db.First(&user, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      user.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateUser{Answer: UserMessage, Data: user}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	var validate = validator.New()
	if err := validate.Struct(user); err != nil {
		UserMessage = model.ResponseUser{
			ID:      user.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateUser{Answer: UserMessage, Data: user}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	if err := c.ShouldBindJSON(&user); err != nil {
		UserMessage = model.ResponseUser{
			ID:      user.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateUser{Answer: UserMessage, Data: user}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Save(&user)
	UserMessage = model.ResponseUser{
		ID:      user.ID,
		Message: "User Updated successfully",
	}
	Response = model.ResponseUserCreateUser{Answer: UserMessage, Data: user}
	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Delete a user
// @Description Delete a user record
// @Tags User
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateUser
// @Failure 503 {object} model.ResponseUserCreateUser "Технические шоколадки"
// @Param body body model.User true "User object that needs to be deleted"
// / @Param        id   path      int  true  "Account ID"
// @Router /user/{id} [delete]
// @Security Bearer
func DeleteUser(c *gin.Context) {
	id := c.Params.ByName("id")
	var user model.User
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateUser
	result := db.First(&user, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      user.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateUser{Answer: UserMessage, Data: user}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	db.Delete(&user, id)
	UserMessage = model.ResponseUser{
		ID:      user.ID,
		Message: "user Deleted successfully",
	}
	Response = model.ResponseUserCreateUser{Answer: UserMessage, Data: user}
	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary Create a new practice
// @Description Create a new practice record
// @Tags Practices
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePractice
// @Failure 503 {object} model.ResponseUserCreatePractice "Технические шоколадки"
// @Param body body model.Practices true "Practice object that needs to be created"
// @Router /practice [post]
// @Security Bearer
func CreatePractice(c *gin.Context) {
	var practice model.Practices
	//if err := c.ShouldBindJSON(&practice); err != nil {
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	//	return
	//}
	//db.Create(&practice)
	//c.JSON(http.StatusOK, gin.H{"message": "Practice created successfully", "data": practice})

	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePractice
	if err := c.ShouldBindJSON(&practice); err != nil {
		UserMessage = model.ResponseUser{
			ID:      practice.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatePractice{Answer: UserMessage, Data: practice}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	var validate = validator.New()
	if err := validate.Struct(practice); err != nil {
		UserMessage = model.ResponseUser{
			ID:      practice.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatePractice{Answer: UserMessage, Data: practice}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Create(&practice)
	UserMessage = model.ResponseUser{
		ID:      practice.ID,
		Message: "practice created successfully",
	}
	Response = model.ResponseUserCreatePractice{Answer: UserMessage, Data: practice}

	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Read a practice by id
// @Description Reading a practice item by id
// @Tags Practices
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePractice
// @Failure 503 {object} model.ResponseUserCreatePractice "Технические шоколадки"
// @Param        id   path      int  true  "Account ID"
// @Router /practice/{id} [get]
// @Security Bearer
func ReadPracticeByID(c *gin.Context) {
	id := c.Params.ByName("id")
	var practice model.Practices
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePractice
	result := db.First(&practice, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      practice.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreatePractice{Answer: UserMessage, Data: practice}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}
	UserMessage = model.ResponseUser{
		ID:      practice.ID,
		Message: "Record found succes",
	}
	Response = model.ResponseUserCreatePractice{Answer: UserMessage, Data: practice}

	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary Update a practice
// @Description Update a practice record
// @Tags Practices
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePractice
// @Failure 503 {object} model.ResponseUserCreatePractice "Технические шоколадки"
// @Param body body model.Practices true "Practice object that needs to be updated"
// / @Param        id   path      int  true  "Account ID"
// @Router /practice/{id} [put]
// @Security Bearer
func UpdatePractice(c *gin.Context) {
	id := c.Params.ByName("id")
	var practice model.Practices
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePractice
	result := db.First(&practice, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      practice.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreatePractice{Answer: UserMessage, Data: practice}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	var validate = validator.New()
	if err := validate.Struct(practice); err != nil {
		UserMessage = model.ResponseUser{
			ID:      practice.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatePractice{Answer: UserMessage, Data: practice}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	if err := c.ShouldBindJSON(&practice); err != nil {
		UserMessage = model.ResponseUser{
			ID:      practice.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatePractice{Answer: UserMessage, Data: practice}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Save(&practice)
	UserMessage = model.ResponseUser{
		ID:      practice.ID,
		Message: "Practice Updated successfully",
	}
	Response = model.ResponseUserCreatePractice{Answer: UserMessage, Data: practice}
	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Delete a practice
// @Description Delete a practice record
// @Tags Practices
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePractice
// @Failure 503 {object} model.ResponseUserCreatePractice "Технические шоколадки"
// @Param body body model.Practices true "Practice object that needs to be deleted"
// / @Param        id   path      int  true  "Account ID"
// @Router /practice/{id} [delete]
// @Security Bearer
func DeletePractice(c *gin.Context) {
	id := c.Params.ByName("id")
	var practice model.Practices
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePractice
	result := db.First(&practice, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      practice.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreatePractice{Answer: UserMessage, Data: practice}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	db.Delete(&practice, id)
	UserMessage = model.ResponseUser{
		ID:      practice.ID,
		Message: "Practice Deleted successfully",
	}
	Response = model.ResponseUserCreatePractice{Answer: UserMessage, Data: practice}
	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary Create a new practice configuration
// @Description Create a new practice configuration record
// @Tags PracticeConfig
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePracticeConfig
// @Failure 503 {object} model.ResponseUserCreatePracticeConfig "Технические шоколадки"
// @Param body body model.PracticeConfig true "PracticeConfig object that needs to be created"
// @Router /practiceconfig [post]
// @Security Bearer
func CreatePracticeConfig(c *gin.Context) {
	var practiceConfig model.PracticeConfig
	//if err := c.ShouldBindJSON(&practiceConfig); err != nil {
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	//	return
	//}
	//db.Create(&practiceConfig)
	//c.JSON(http.StatusOK, gin.H{"message": "PracticeConfig created successfully", "data": practiceConfig})

	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePracticeConfig
	if err := c.ShouldBindJSON(&practiceConfig); err != nil {
		UserMessage = model.ResponseUser{
			ID:      practiceConfig.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatePracticeConfig{Answer: UserMessage, Data: practiceConfig}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	var validate = validator.New()
	if err := validate.Struct(practiceConfig); err != nil {
		UserMessage = model.ResponseUser{
			ID:      practiceConfig.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatePracticeConfig{Answer: UserMessage, Data: practiceConfig}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Create(&practiceConfig)
	UserMessage = model.ResponseUser{
		ID:      practiceConfig.ID,
		Message: "Practice Config created successfully",
	}
	Response = model.ResponseUserCreatePracticeConfig{Answer: UserMessage, Data: practiceConfig}

	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Read a practice configuration by id
// @Description Reading a practice configuration item by id
// @Tags PracticeConfig
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePracticeConfig
// @Failure 503 {object} model.ResponseUserCreatePracticeConfig "Технические шоколадки"
// @Param        id   path      int  true  "Account ID"
// @Router /practiceconfig/{id} [get]
// @Security Bearer
func ReadPracticeConfigByID(c *gin.Context) {
	id := c.Params.ByName("id")
	var practiceConfig model.PracticeConfig
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePracticeConfig
	result := db.First(&practiceConfig, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      practiceConfig.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreatePracticeConfig{Answer: UserMessage, Data: practiceConfig}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}
	UserMessage = model.ResponseUser{
		ID:      practiceConfig.ID,
		Message: "Record found succes",
	}
	Response = model.ResponseUserCreatePracticeConfig{Answer: UserMessage, Data: practiceConfig}

	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary Update a practice configuration
// @Description Update a practice configuration record
// @Tags PracticeConfig
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePracticeConfig
// @Failure 503 {object} model.ResponseUserCreatePracticeConfig "Технические шоколадки"
// @Param body body model.PracticeConfig true "PracticeConfig object that needs to be updated"
// / @Param        id   path      int  true  "Account ID"
// @Router /practiceconfig/{id} [put]
// @Security Bearer
func UpdatePracticeConfig(c *gin.Context) {
	id := c.Params.ByName("id")
	var practiceConfig model.PracticeConfig
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePracticeConfig
	result := db.First(&practiceConfig, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      practiceConfig.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreatePracticeConfig{Answer: UserMessage, Data: practiceConfig}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	var validate = validator.New()
	if err := validate.Struct(practiceConfig); err != nil {
		UserMessage = model.ResponseUser{
			ID:      practiceConfig.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatePracticeConfig{Answer: UserMessage, Data: practiceConfig}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	if err := c.ShouldBindJSON(&practiceConfig); err != nil {
		UserMessage = model.ResponseUser{
			ID:      practiceConfig.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatePracticeConfig{Answer: UserMessage, Data: practiceConfig}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Save(&practiceConfig)
	UserMessage = model.ResponseUser{
		ID:      practiceConfig.ID,
		Message: "PracticeConfig Updated successfully",
	}
	Response = model.ResponseUserCreatePracticeConfig{Answer: UserMessage, Data: practiceConfig}
	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Delete a practice configuration
// @Description Delete a practice configuration record
// @Tags PracticeConfig
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePracticeConfig
// @Failure 503 {object} model.ResponseUserCreatePracticeConfig "Технические шоколадки"
// @Param body body model.PracticeConfig true "PracticeConfig object that needs to be deleted"
// / @Param        id   path      int  true  "Account ID"
// @Router /practiceconfig/{id} [delete]
// @Security Bearer
func DeletePracticeConfig(c *gin.Context) {
	id := c.Params.ByName("id")
	var practiceConfig model.PracticeConfig
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePracticeConfig
	result := db.First(&practiceConfig, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      practiceConfig.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreatePracticeConfig{Answer: UserMessage, Data: practiceConfig}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	db.Delete(&practiceConfig, id)
	UserMessage = model.ResponseUser{
		ID:      practiceConfig.ID,
		Message: "Practice config Deleted successfully",
	}
	Response = model.ResponseUserCreatePracticeConfig{Answer: UserMessage, Data: practiceConfig}
	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary Create a new practice day
// @Description Create a new practice day record
// @Tags PracticeDays
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePracticedays
// @Failure 503 {object} model.ResponseUserCreatePracticedays "Технические шоколадки"
// @Param body body model.PracticeDays true "PracticeDay object that needs to be created"
// @Router /practiceday [post]
// @Security Bearer
func CreatePracticeDay(c *gin.Context) {
	var days model.PracticeDays
	//if err := c.ShouldBindJSON(&days); err != nil {
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	//	return
	//}
	//db.Create(&days)
	//c.JSON(http.StatusOK, gin.H{"message": "PracticeDay created successfully", "data": days})

	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePracticedays
	if err := c.ShouldBindJSON(&days); err != nil {
		UserMessage = model.ResponseUser{
			ID:      days.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatePracticedays{Answer: UserMessage, Data: days}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	var validate = validator.New()
	if err := validate.Struct(days); err != nil {
		UserMessage = model.ResponseUser{
			ID:      days.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatePracticedays{Answer: UserMessage, Data: days}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Create(&days)
	UserMessage = model.ResponseUser{
		ID:      days.ID,
		Message: "Days created successfully",
	}
	Response = model.ResponseUserCreatePracticedays{Answer: UserMessage, Data: days}

	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Read a practice day by id
// @Description Reading a practice day item by id
// @Tags PracticeDays
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePracticedays
// @Failure 503 {object} model.ResponseUserCreatePracticedays "Технические шоколадки"
// @Param        id   path      int  true  "Account ID"
// @Router /practiceday/{id} [get]
// @Security Bearer
func ReadPracticeDayByID(c *gin.Context) {
	id := c.Params.ByName("id")
	var days model.PracticeDays
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePracticedays
	result := db.First(&days, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      days.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreatePracticedays{Answer: UserMessage, Data: days}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}
	UserMessage = model.ResponseUser{
		ID:      days.ID,
		Message: "Record found succes",
	}
	Response = model.ResponseUserCreatePracticedays{Answer: UserMessage, Data: days}

	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary Update a practice day
// @Description Update a practice day record
// @Tags PracticeDays
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePracticedays
// @Failure 503 {object} model.ResponseUserCreatePracticedays "Технические шоколадки"
// @Param body body model.PracticeDays true "PracticeDay object that needs to be updated"
// / @Param        id   path      int  true  "Account ID"
// @Router /practiceday/{id} [put]
// @Security Bearer
func UpdatePracticeDay(c *gin.Context) {
	id := c.Params.ByName("id")
	var days model.PracticeDays
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePracticedays
	result := db.First(&days, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      days.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreatePracticedays{Answer: UserMessage, Data: days}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	var validate = validator.New()
	if err := validate.Struct(days); err != nil {
		UserMessage = model.ResponseUser{
			ID:      days.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatePracticedays{Answer: UserMessage, Data: days}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	if err := c.ShouldBindJSON(&days); err != nil {
		UserMessage = model.ResponseUser{
			ID:      days.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatePracticedays{Answer: UserMessage, Data: days}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Save(&days)
	UserMessage = model.ResponseUser{
		ID:      days.ID,
		Message: "Days Updated successfully",
	}
	Response = model.ResponseUserCreatePracticedays{Answer: UserMessage, Data: days}
	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Delete a practice day
// @Description Delete a practice day record
// @Tags PracticeDays
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatePracticedays
// @Failure 503 {object} model.ResponseUserCreatePracticedays "Технические шоколадки"
// @Param body body model.PracticeDays true "PracticeDay object that needs to be deleted"
// / @Param        id   path      int  true  "Account ID"
// @Router /practiceday/{id} [delete]
// @Security Bearer
func DeletePracticeDay(c *gin.Context) {
	id := c.Params.ByName("id")
	var days model.PracticeDays
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatePracticedays
	result := db.First(&days, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      days.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreatePracticedays{Answer: UserMessage, Data: days}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	db.Delete(&days, id)
	UserMessage = model.ResponseUser{
		ID:      days.ID,
		Message: "Days Deleted successfully",
	}
	Response = model.ResponseUserCreatePracticedays{Answer: UserMessage, Data: days}
	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// Пример для таблицы PracticeShedule

// @Summary Create a new practice schedule
// @Description Create a new practice schedule record
// @Tags PracticeShedule
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatepracticeShedule
// @Failure 503 {object} model.ResponseUserCreatepracticeShedule "Технические шоколадки"
// @Param body body model.PracticeShedule true "PracticeShedule object that needs to be created"
// @Router /practiceschedule [post]
// @Security Bearer
func CreatePracticeShedule(c *gin.Context) {
	var shedule model.PracticeShedule
	//if err := c.ShouldBindJSON(&shedule); err != nil {
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	//	return
	//}
	//db.Create(&shedule)
	//c.JSON(http.StatusOK, gin.H{"message": "PracticeShedule created successfully", "data": shedule})

	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatepracticeShedule
	if err := c.ShouldBindJSON(&shedule); err != nil {
		UserMessage = model.ResponseUser{
			ID:      shedule.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatepracticeShedule{Answer: UserMessage, Data: shedule}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	var validate = validator.New()
	if err := validate.Struct(shedule); err != nil {
		UserMessage = model.ResponseUser{
			ID:      shedule.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatepracticeShedule{Answer: UserMessage, Data: shedule}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Create(&shedule)
	UserMessage = model.ResponseUser{
		ID:      shedule.ID,
		Message: "Shedule created successfully",
	}
	Response = model.ResponseUserCreatepracticeShedule{Answer: UserMessage, Data: shedule}

	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Read a practice schedule by id
// @Description Reading a practice schedule item by id
// @Tags PracticeShedule
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatepracticeShedule
// @Failure 503 {object} model.ResponseUserCreatepracticeShedule "Технические шоколадки"
// @Param        id   path      int  true  "Account ID"
// @Router /practiceschedule/{id} [get]
// @Security Bearer
func ReadPracticeSheduleByID(c *gin.Context) {
	id := c.Params.ByName("id")
	var shedule model.PracticeShedule
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatepracticeShedule
	result := db.First(&shedule, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      shedule.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreatepracticeShedule{Answer: UserMessage, Data: shedule}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}
	UserMessage = model.ResponseUser{
		ID:      shedule.ID,
		Message: "Record found succes",
	}
	Response = model.ResponseUserCreatepracticeShedule{Answer: UserMessage, Data: shedule}

	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary Update a practice schedule
// @Description Update a practice schedule record
// @Tags PracticeShedule
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatepracticeShedule
// @Failure 503 {object} model.ResponseUserCreatepracticeShedule "Технические шоколадки"
// @Param body body model.PracticeShedule true "PracticeShedule object that needs to be updated"
// / @Param        id   path      int  true  "Account ID"
// @Router /practiceschedule/{id} [put]
// @Security Bearer
func UpdatePracticeShedule(c *gin.Context) {
	id := c.Params.ByName("id")
	var shedule model.PracticeShedule
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatepracticeShedule
	result := db.First(&shedule, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      shedule.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreatepracticeShedule{Answer: UserMessage, Data: shedule}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	var validate = validator.New()
	if err := validate.Struct(shedule); err != nil {
		UserMessage = model.ResponseUser{
			ID:      shedule.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatepracticeShedule{Answer: UserMessage, Data: shedule}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	if err := c.ShouldBindJSON(&shedule); err != nil {
		UserMessage = model.ResponseUser{
			ID:      shedule.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreatepracticeShedule{Answer: UserMessage, Data: shedule}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Save(&shedule)
	UserMessage = model.ResponseUser{
		ID:      shedule.ID,
		Message: "Shedule Updated successfully",
	}
	Response = model.ResponseUserCreatepracticeShedule{Answer: UserMessage, Data: shedule}
	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Delete a practice schedule
// @Description Delete a practice schedule record
// @Tags PracticeShedule
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreatepracticeShedule
// @Failure 503 {object} model.ResponseUserCreatepracticeShedule "Технические шоколадки"
// @Param body body model.PracticeShedule true "PracticeShedule object that needs to be deleted"
// / @Param        id   path      int  true  "Account ID"
// @Router /practiceschedule/:{id} [delete]
// @Security Bearer
func DeletePracticeShedule(c *gin.Context) {
	id := c.Params.ByName("id")
	var shedule model.PracticeShedule
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreatepracticeShedule
	result := db.First(&shedule, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      shedule.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreatepracticeShedule{Answer: UserMessage, Data: shedule}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	db.Delete(&shedule, id)
	UserMessage = model.ResponseUser{
		ID:      shedule.ID,
		Message: "Shedule Deleted successfully",
	}
	Response = model.ResponseUserCreatepracticeShedule{Answer: UserMessage, Data: shedule}
	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// Пример CRUD операций для таблицы Logs

// @Summary Create a new log entry
// @Description Create a new log entry record
// @Tags Logs
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateLogs
// @Failure 503 {object} model.ResponseUserCreateLogs "Технические шоколадки"
// @Param body body model.Logs true "Logs object that needs to be created"
// @Router /logs [post]
// @Security Bearer
func CreateLogEntry(c *gin.Context) {
	var logs model.Logs
	//if err := c.ShouldBindJSON(&logs); err != nil {
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	//	return
	//}
	//db.Create(&logs)
	//c.JSON(http.StatusOK, gin.H{"message": "LogEntry created successfully", "data": logs})

	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateLogs
	if err := c.ShouldBindJSON(&logs); err != nil {
		UserMessage = model.ResponseUser{
			ID:      logs.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateLogs{Answer: UserMessage, Data: logs}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	var validate = validator.New()
	if err := validate.Struct(logs); err != nil {
		UserMessage = model.ResponseUser{
			ID:      logs.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateLogs{Answer: UserMessage, Data: logs}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Create(&logs)
	UserMessage = model.ResponseUser{
		ID:      logs.ID,
		Message: "Logs created successfully",
	}
	Response = model.ResponseUserCreateLogs{Answer: UserMessage, Data: logs}

	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Read a log entry by id
// @Description Reading a log entry item by id
// @Tags Logs
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateLogs
// @Failure 503 {object} model.ResponseUserCreateLogs "Технические шоколадки"
// @Param        id   path      int  true  "Account ID"
// @Router /logs/{id} [get]
// @Security Bearer
func ReadLogEntryByID(c *gin.Context) {
	id := c.Params.ByName("id")
	var logs model.Logs
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateLogs
	result := db.First(&logs, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      logs.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateLogs{Answer: UserMessage, Data: logs}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}
	UserMessage = model.ResponseUser{
		ID:      logs.ID,
		Message: "Record found succes",
	}
	Response = model.ResponseUserCreateLogs{Answer: UserMessage, Data: logs}

	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary Update a log entry
// @Description Update a log entry record
// @Tags Logs
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateLogs
// @Failure 503 {object} model.ResponseUserCreateLogs "Технические шоколадки"
// @Param body body model.Logs true "Logs object that needs to be updated"
// / @Param        id   path      int  true  "Account ID"
// @Router /logs/{id} [put]
// @Security Bearer
func UpdateLogEntry(c *gin.Context) {
	id := c.Params.ByName("id")
	var logs model.Logs
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateLogs
	result := db.First(&logs, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      logs.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateLogs{Answer: UserMessage, Data: logs}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	var validate = validator.New()
	if err := validate.Struct(logs); err != nil {
		UserMessage = model.ResponseUser{
			ID:      logs.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateLogs{Answer: UserMessage, Data: logs}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	if err := c.ShouldBindJSON(&logs); err != nil {
		UserMessage = model.ResponseUser{
			ID:      logs.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateLogs{Answer: UserMessage, Data: logs}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Save(&logs)
	UserMessage = model.ResponseUser{
		ID:      logs.ID,
		Message: "Logs Updated successfully",
	}
	Response = model.ResponseUserCreateLogs{Answer: UserMessage, Data: logs}
	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Delete a log entry
// @Description Delete a log entry record
// @Tags Logs
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateLogs
// @Failure 503 {object} model.ResponseUserCreateLogs "Технические шоколадки"
// @Param body body model.Logs true "Logs object that needs to be deleted"
// / @Param        id   path      int  true  "Account ID"
// @Router /logs/{id} [delete]
// @Security Bearer
func DeleteLogEntry(c *gin.Context) {
	id := c.Params.ByName("id")
	var logs model.Logs
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateLogs
	result := db.First(&logs, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      logs.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateLogs{Answer: UserMessage, Data: logs}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	db.Delete(&logs, id)
	UserMessage = model.ResponseUser{
		ID:      logs.ID,
		Message: "Log Deleted successfully",
	}
	Response = model.ResponseUserCreateLogs{Answer: UserMessage, Data: logs}
	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary Create a new status
// @Description Create a new status record
// @Tags Status
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateStatus
// @Failure 503 {object} model.ResponseUserCreateStatus "Технические шоколадки"
// @Param body body model.Status true "Status object that needs to be created"
// @Router /status [post]
// @Security Bearer
func CreateStatus(c *gin.Context) {
	var status model.Status
	//if err := c.ShouldBindJSON(&status); err != nil {
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	//	return
	//}
	//db.Create(&status)
	//c.JSON(http.StatusOK, gin.H{"message": "LogEntry created successfully", "data": status})

	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateStatus
	if err := c.ShouldBindJSON(&status); err != nil {
		UserMessage = model.ResponseUser{
			ID:      status.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateStatus{Answer: UserMessage, Data: status}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	var validate = validator.New()
	if err := validate.Struct(status); err != nil {
		UserMessage = model.ResponseUser{
			ID:      status.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateStatus{Answer: UserMessage, Data: status}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Create(&status)
	UserMessage = model.ResponseUser{
		ID:      status.ID,
		Message: "Status created successfully",
	}
	Response = model.ResponseUserCreateStatus{Answer: UserMessage, Data: status}

	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Read a status by id
// @Description Reading a status item by id
// @Tags Status
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateStatus
// @Failure 503 {object} model.ResponseUserCreateStatus "Технические шоколадки"
// @Param        id   path      int  true  "Account ID"
// @Router /status/{id} [get]
// @Security Bearer
func ReadStatusByID(c *gin.Context) {
	id := c.Params.ByName("id")
	var status model.Status
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateStatus
	result := db.First(&status, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      status.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateStatus{Answer: UserMessage, Data: status}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}
	UserMessage = model.ResponseUser{
		ID:      status.ID,
		Message: "Record found succes",
	}
	Response = model.ResponseUserCreateStatus{Answer: UserMessage, Data: status}

	c.JSON(http.StatusOK, gin.H{"message": Response})
}

// @Summary Update a status
// @Description Update a status record
// @Tags Status
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateStatus
// @Failure 503 {object} model.ResponseUserCreateStatus "Технические шоколадки"
// @Param body body model.Status true "Status object that needs to be updated"
// / @Param        id   path      int  true  "Account ID"
// @Router /status/{id} [put]
// @Security Bearer
func UpdateStatus(c *gin.Context) {
	id := c.Params.ByName("id")
	var status model.Status
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateStatus
	result := db.First(&status, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      status.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateStatus{Answer: UserMessage, Data: status}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	var validate = validator.New()
	if err := validate.Struct(status); err != nil {
		UserMessage = model.ResponseUser{
			ID:      status.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateStatus{Answer: UserMessage, Data: status}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	if err := c.ShouldBindJSON(&status); err != nil {
		UserMessage = model.ResponseUser{
			ID:      status.ID,
			Message: err.Error(),
		}
		Response = model.ResponseUserCreateStatus{Answer: UserMessage, Data: status}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
		return
	}

	db.Save(&status)
	UserMessage = model.ResponseUser{
		ID:      status.ID,
		Message: "Status Updated successfully",
	}
	Response = model.ResponseUserCreateStatus{Answer: UserMessage, Data: status}
	c.JSON(http.StatusOK, gin.H{"Message": Response})
}

// @Summary Delete a status
// @Description Delete a status record
// @Tags Status
// @Accept json
// @Produce json
// @Success      200  {array}  model.ResponseUserCreateStatus
// @Failure 503 {object} model.ResponseUserCreateStatus "Технические шоколадки"
// @Param body body model.Status true "Status object that needs to be deleted"
// / @Param        id   path      int  true  "Account ID"
// @Router /status/{id} [delete]
// @Security Bearer
func DeleteStatus(c *gin.Context) {
	id := c.Params.ByName("id")
	var status model.Status
	var UserMessage model.ResponseUser
	var Response model.ResponseUserCreateStatus
	result := db.First(&status, id)
	if result.Error != nil {
		UserMessage = model.ResponseUser{
			ID:      status.ID,
			Message: "Record not found",
		}
		Response = model.ResponseUserCreateStatus{Answer: UserMessage, Data: status}
		c.JSON(http.StatusBadRequest, gin.H{"error": Response})
	}

	db.Delete(&status, id)
	UserMessage = model.ResponseUser{
		ID:      status.ID,
		Message: "Status Deleted successfully",
	}
	Response = model.ResponseUserCreateStatus{Answer: UserMessage, Data: status}
	c.JSON(http.StatusOK, gin.H{"message": Response})
}
