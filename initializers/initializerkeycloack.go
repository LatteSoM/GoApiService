package initializers

import (
	"context"
	"github.com/Nerzal/gocloak/v13"
)

var (
	ClientKeyCloak *gocloak.GoCloak
	Ctx            context.Context
	Token          *gocloak.JWT
)

//func KeyCloackInitializer() {
//	ClientKeyCloak = gocloak.NewClient(os.Getenv("REALM_URL"))
//
//	var err error
//	Token, err = ClientKeyCloak.LoginAdmin(Ctx, os.Getenv("ADMIN_USERNAME"), os.Getenv("ADMIN_PASSWORD"), os.Getenv("ADMIN_REALM_NAME"))
//	if err != nil {
//		log.Println("keycloak admin: ", err)
//		//return
//	}
//	log.Println("success login admin")
//}
