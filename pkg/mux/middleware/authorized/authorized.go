package authorized

import (
	"github.com/jafarsirojov/core-olinebank-chat/pkg/core/token"
	"context"
	"log"
	"net/http"
)

func Authorized(roles []string, payload func(ctx context.Context) interface{}) func(next http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, request *http.Request) {
			// TODO: || [ROLE_ADMIN, ROLE_MODERATOR] -> [ROLE_ADMIN, ROLE_USER]
			// TODO: лучше убрать жёстку завязку на структуру token payload и определить либо интерфейс, либо reflection
			auth := payload(request.Context()).(*token.Payload)
			for _, role := range roles {
				for _, r := range auth.Roles {
					if role == r {
						log.Printf("access granted %v %v", roles, auth)
						next(writer, request)
						return
					}
				}
			}

			http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
}
