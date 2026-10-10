package policy

import (
	"fmt"
	"slices"

	agentv1 "github.com/Exonical/sigil/backend/gen/sigil/agent/v1"
	"github.com/Exonical/sigil/backend/internal/db"
)

type Request struct {
	Roles                 []string
	Station               db.Station
	Token                 *db.Token
	Operation             agentv1.Operation
	UserID                string
	SelfServiceOperations []string
}

type Decision struct {
	Allowed bool
	Reason  string
}

type Engine interface {
	Authorize(Request) Decision
}

type LocalPolicy struct{}

func (LocalPolicy) Authorize(request Request) Decision {
	return Authorize(request)
}

func Authorize(request Request) Decision {
	if request.Station.Status != "active" {
		return Decision{Reason: "station is not active"}
	}
	if request.Token == nil {
		return Decision{Reason: "token is not in inventory"}
	}
	if request.Token.Status == "lost" || request.Token.Status == "retired" {
		return Decision{Reason: fmt.Sprintf("token status %q is not eligible", request.Token.Status)}
	}
	if !isPIVOperation(request.Operation) {
		return Decision{Reason: "only PIV operations are grantable"}
	}
	if request.Station.Mode == "station" &&
		(hasRole(request.Roles, "admin") || hasRole(request.Roles, "helpdesk")) {
		if request.Token.Status != "active" && request.Token.Status != "unassigned" {
			return Decision{Reason: "token status is not eligible at a station"}
		}
		return Decision{Allowed: true, Reason: "station operator authorized"}
	}
	operationName := agentv1.Operation_name[int32(request.Operation)]
	if slices.Contains(request.SelfServiceOperations, operationName) &&
		request.Token.Status == "active" &&
		request.Token.AssignedUserID != nil &&
		*request.Token.AssignedUserID == request.UserID {
		return Decision{Allowed: true, Reason: "self-service operation authorized for assigned token"}
	}
	return Decision{Reason: "user is not authorized for this operation on this token"}
}

func isPIVOperation(operation agentv1.Operation) bool {
	switch operation {
	case agentv1.Operation_PIV_GENERATE_KEY,
		agentv1.Operation_PIV_IMPORT_CERTIFICATE,
		agentv1.Operation_PIV_DELETE_CERTIFICATE,
		agentv1.Operation_PIV_UNBLOCK_PIN,
		agentv1.Operation_PIV_CHANGE_PUK,
		agentv1.Operation_PIV_CHANGE_MANAGEMENT_KEY,
		agentv1.Operation_PIV_SET_RETRIES,
		agentv1.Operation_PIV_DELETE_KEY,
		agentv1.Operation_PIV_MANAGED_INITIALIZE:
		return true
	default:
		return false
	}
}

func hasRole(roles []string, role string) bool {
	return slices.Contains(roles, role)
}
